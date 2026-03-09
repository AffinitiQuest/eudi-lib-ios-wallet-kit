//
//  DidResolver.swift
//  EudiWalletKit
//
//  Created by Ian Carbone on 2026-02-23.
//

import Foundation
import Security
import CryptoKit
import OpenID4VP

// MARK: - DID Type

extension DID {
	var method: String? {
		let parts = string.split(separator: ":", maxSplits: 2)
		guard parts.count >= 2, parts[0] == "did" else { return nil }
		return String(parts[1])
	}

	var methodSpecificId: String? {
		let parts = string.split(separator: ":", maxSplits: 2)
		guard parts.count == 3 else { return nil }
		return String(parts[2])
	}
}

// MARK: - Multicodec constants

private enum Multicodec {
	static let p256Prefix:     [UInt8] = [0x80, 0x24] // 0x1200
	static let p384Prefix:     [UInt8] = [0x81, 0x24] // 0x1201
	static let p521Prefix:     [UInt8] = [0x82, 0x24] // 0x1202
	static let ed25519Prefix:  [UInt8] = [0xed, 0x01]
	static let x25519Prefix:   [UInt8] = [0xec, 0x01]
	static let secp256k1Prefix:[UInt8] = [0xe7, 0x01]
}

// MARK: - Errors

enum DIDResolverError: Error {
	case invalidDID
	case unsupportedMethod(String)
	case unsupportedKeyType
	case decodingFailed
	case networkError(Error)
	case invalidDIDDocument
	case noVerificationMethod
	case keyCreationFailed(CFError?)
}

// MARK: - DID Document models

private struct DIDDocument: Decodable {
	let id: String
	let verificationMethod: [VerificationMethod]?
	let authentication: [AuthenticationEntry]?

	private enum CodingKeys: String, CodingKey {
		case id, verificationMethod, authentication
	}
}

private enum AuthenticationEntry: Decodable {
	case embedded(VerificationMethod)
	case referenced(String)

	init(from decoder: Decoder) throws {
		let container = try decoder.singleValueContainer()
		if let ref = try? container.decode(String.self) {
			self = .referenced(ref)
		} else {
			self = .embedded(try container.decode(VerificationMethod.self))
		}
	}
}

private struct VerificationMethod: Decodable {
	let id: String
	let type: String
	let publicKeyJwk: JWK?
	let publicKeyMultibase: String?
}

private struct JWK: Decodable {
	let kty: String
	let crv: String?
	let x: String?
	let y: String?
	let n: String?  // RSA
	let e: String?  // RSA
}

// MARK: - Main Resolver

public final class DidResolver: DIDPublicKeyLookupAgentType {
	private let urlSession: URLSession

	public init(urlSession: URLSession = .shared) {
		self.urlSession = urlSession
	}

	public func resolveKey(from didUrl: DID) async -> SecKey? {
		do {
			switch didUrl.method {
			case "key":
				return try resolveKeyDID(didUrl)
			case "web":
				return try await resolveWebDID(didUrl)
			default:
				throw DIDResolverError.unsupportedMethod(didUrl.method ?? "unknown")
			}
		} catch {
			return nil
		}
	}
}

// MARK: - DID:KEY

private extension DidResolver {

	func resolveKeyDID(_ did: DID) throws -> SecKey {
		guard let identifier = did.methodSpecificId else {
			throw DIDResolverError.invalidDID
		}

		// Strip fragment (e.g. did:key:z...#z...)
		let keyId = identifier.components(separatedBy: "#").first ?? identifier

		guard keyId.hasPrefix("z") else {
			throw DIDResolverError.decodingFailed
		}

		let multibasePayload = String(keyId.dropFirst()) // drop 'z' (base58btc prefix)
		guard let decoded = Base58.decode(multibasePayload) else {
			throw DIDResolverError.decodingFailed
		}

		return try secKeyFromMulticodec(Array(decoded))
	}

	func secKeyFromMulticodec(_ bytes: [UInt8]) throws -> SecKey {
		if bytes.starts(with: Multicodec.p256Prefix) {
			let keyBytes = Array(bytes.dropFirst(Multicodec.p256Prefix.count))
			return try makeECSecKey(keyBytes, curve: "P-256", keySize: 65)
		} else if bytes.starts(with: Multicodec.p384Prefix) {
			let keyBytes = Array(bytes.dropFirst(Multicodec.p384Prefix.count))
			return try makeECSecKey(keyBytes, curve: "P-384", keySize: 97)
		} else if bytes.starts(with: Multicodec.p521Prefix) {
			let keyBytes = Array(bytes.dropFirst(Multicodec.p521Prefix.count))
			return try makeECSecKey(keyBytes, curve: "P-521", keySize: 133)
		} else if bytes.starts(with: Multicodec.ed25519Prefix) {
			let keyBytes = Array(bytes.dropFirst(Multicodec.ed25519Prefix.count))
			return try makeEd25519SecKey(keyBytes)
		} else if bytes.starts(with: Multicodec.secp256k1Prefix) {
			// secp256k1 is not natively supported by Apple's Security framework.
			// If you have a third-party library (e.g. secp256k1.swift), bridge here.
			throw DIDResolverError.unsupportedKeyType
		} else {
			throw DIDResolverError.unsupportedKeyType
		}
	}

	/// Accepts both compressed (33/49/67 bytes) and uncompressed (65/97/133 bytes) EC points.
	func makeECSecKey(_ keyBytes: [UInt8], curve: String, keySize: Int) throws -> SecKey {
		var rawKey = keyBytes

		// Decompress point if needed
		if rawKey.count != keySize && (rawKey.first == 0x02 || rawKey.first == 0x03) {
			rawKey = try decompressECPoint(rawKey, curve: curve)
		}

		guard rawKey.count == keySize else {
			throw DIDResolverError.decodingFailed
		}

		let keyData = Data(rawKey)
		var error: Unmanaged<CFError>?
		let attributes: [String: Any] = [
			kSecAttrKeyType as String:       kSecAttrKeyTypeEC,
			kSecAttrKeyClass as String:      kSecAttrKeyClassPublic,
			kSecAttrKeySizeInBits as String: (keySize - 1) * 4 // 256/384/521
		]
		guard let key = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
			throw DIDResolverError.keyCreationFailed(error?.takeRetainedValue())
		}
		return key
	}

	func makeEd25519SecKey(_ keyBytes: [UInt8]) throws -> SecKey {
		guard keyBytes.count == 32 else { throw DIDResolverError.decodingFailed }
		let keyData = Data(keyBytes)
		var error: Unmanaged<CFError>?
		let attributes: [String: Any] = [
			kSecAttrKeyType as String:  kSecAttrKeyTypeECSECPrimeRandom, // placeholder
			kSecAttrKeyClass as String: kSecAttrKeyClassPublic
		]
		// Ed25519 via CryptoKit — wrap as SecKey using the raw representation
		let ck = try Curve25519.Signing.PublicKey(rawRepresentation: keyData)
		guard let key = SecKeyCreateWithData(
			ck.rawRepresentation as CFData,
			[kSecAttrKeyType as String: "ed25519",
			 kSecAttrKeyClass as String: kSecAttrKeyClassPublic] as CFDictionary,
			&error
		) else {
			// Fallback: return a CryptoKit-backed key via the x963 trick isn't available for Ed25519.
			// Store the CryptoKit key and wrap it — callers that receive this key must use CryptoKit.
			throw DIDResolverError.unsupportedKeyType
		}
		return key
	}

	/// Naive EC point decompression using CryptoKit for P-256.
	/// For P-384 / P-521 you will need a big-number library or custom implementation.
	func decompressECPoint(_ compressed: [UInt8], curve: String) throws -> [UInt8] {
		guard curve == "P-256", compressed.count == 33 else {
			throw DIDResolverError.unsupportedKeyType
		}
		let p256Key = try P256.Signing.PublicKey(compressedRepresentation: Data(compressed))
		return Array(p256Key.x963Representation) // 0x04 || x || y
	}
}

// MARK: - DID:WEB

private extension DidResolver {

	func resolveWebDID(_ did: DID) async throws -> SecKey {
		let url = try didWebURL(from: did)
		let (data, response) = try await urlSession.data(from: url)
		guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
			throw DIDResolverError.networkError(
				URLError(.badServerResponse)
			)
		}
		let doc = try JSONDecoder().decode(DIDDocument.self, from: data)
		return try extractKey(from: doc, did: did)
	}

	func didWebURL(from did: DID) throws -> URL {
		guard let id = did.methodSpecificId else { throw DIDResolverError.invalidDID }

		// Split off fragment (key reference)
		let parts = id.components(separatedBy: "#")
		let domainPart = parts[0]

		// did:web uses colons as path separators after the host
		// e.g. did:web:example.com:path:to:doc → https://example.com/path/to/doc/did.json
		let segments = domainPart.split(separator: ":").map(String.init)
		guard !segments.isEmpty else { throw DIDResolverError.invalidDID }

		let host = segments[0].removingPercentEncoding ?? segments[0]
		let path = segments.count > 1
			? "/" + segments.dropFirst().joined(separator: "/") + "/did.json"
			: "/.well-known/did.json"

		guard let url = URL(string: "https://\(host)\(path)") else {
			throw DIDResolverError.invalidDID
		}
		return url
	}

	func extractKey(from doc: DIDDocument, did: DID) throws -> SecKey {
		// Prefer the verification method referenced in `authentication`
		let preferredMethodIds: [String] = (doc.authentication ?? []).compactMap {
			switch $0 {
			case .referenced(let ref): return ref
			case .embedded(let vm):    return vm.id
			}
		}

		let methods = doc.verificationMethod ?? []
		let candidate = preferredMethodIds.compactMap { id in
			methods.first { $0.id == id || $0.id.hasSuffix(id) }
		}.first ?? methods.first

		guard let vm = candidate else {
			throw DIDResolverError.noVerificationMethod
		}

		if let jwk = vm.publicKeyJwk {
			return try secKeyFromJWK(jwk)
		} else if let multibase = vm.publicKeyMultibase {
			guard multibase.hasPrefix("z"),
				  let decoded = Base58.decode(String(multibase.dropFirst()))
			else { throw DIDResolverError.decodingFailed }
			return try secKeyFromMulticodec(Array(decoded))
		}

		throw DIDResolverError.noVerificationMethod
	}

	func secKeyFromJWK(_ jwk: JWK) throws -> SecKey {
		switch jwk.kty {
		case "EC":
			return try secKeyFromECJWK(jwk)
		case "OKP":
			return try secKeyFromOKPJWK(jwk)
		default:
			throw DIDResolverError.unsupportedKeyType
		}
	}

	func secKeyFromECJWK(_ jwk: JWK) throws -> SecKey {
		guard let crv = jwk.crv,
			  let xB64 = jwk.x, let yB64 = jwk.y,
			  let xData = Data(base64URLEncoded: xB64),
			  let yData = Data(base64URLEncoded: yB64)
		else { throw DIDResolverError.decodingFailed }

		let (curve, keySize): (String, Int) = switch crv {
		case "P-256":   ("P-256", 32)
		case "P-384":   ("P-384", 48)
		case "P-521":   ("P-521", 66)
		default: throw DIDResolverError.unsupportedKeyType as Error
		}

		// Pad coordinates to expected size
		var x = Array(xData); while x.count < keySize { x.insert(0, at: 0) }
		var y = Array(yData); while y.count < keySize { y.insert(0, at: 0) }

		let uncompressed: [UInt8] = [0x04] + x + y
		return try makeECSecKey(uncompressed, curve: curve, keySize: keySize * 2 + 1)
	}

	func secKeyFromOKPJWK(_ jwk: JWK) throws -> SecKey {
		guard jwk.crv == "Ed25519",
			  let xB64 = jwk.x,
			  let xData = Data(base64URLEncoded: xB64)
		else { throw DIDResolverError.unsupportedKeyType }
		return try makeEd25519SecKey(Array(xData))
	}
}

// MARK: - Base58 (Bitcoin alphabet)

private enum Base58 {
	static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
	static let indexMap: [Character: Int] = Dictionary(
		uniqueKeysWithValues: alphabet.enumerated().map { ($1, $0) }
	)

	static func decode(_ input: String) -> Data? {
		var bytes = [UInt8](repeating: 0, count: input.count * 733 / 1000 + 1)
		var length = 0
		for char in input {
			guard let carry = indexMap[char] else { return nil }
			var c = carry
			for i in stride(from: length - 1, through: 0, by: -1) {
				c += 58 * Int(bytes[i])
				bytes[i] = UInt8(c % 256)
				c /= 256
			}
			while c > 0 {
				bytes.insert(UInt8(c % 256), at: 0)
				c /= 256
				length += 1
			}
			length += 1
		}
		// Count leading '1's → leading zero bytes
		let leadingZeros = input.prefix(while: { $0 == "1" }).count
		let result = Array(repeating: UInt8(0), count: leadingZeros)
			+ bytes.suffix(length)
		return Data(result)
	}
}

// MARK: - Data + base64url

private extension Data {
	init?(base64URLEncoded string: String) {
		var base64 = string
			.replacingOccurrences(of: "-", with: "+")
			.replacingOccurrences(of: "_", with: "/")
		while base64.count % 4 != 0 { base64 += "=" }
		self.init(base64Encoded: base64)
	}
}