/*
Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import Foundation
import OrderedCollections
import MdocDataModel18013
import MdocDataTransfer18013
import eudi_lib_sdjwt_swift

public struct DocPresentInfo: Sendable {
	public let docType: String
	public let secureAreaName: String?
	public let docDataFormat: DocDataFormat
	public let displayName: String?
	public let docClaims: [DocClaim]
	public let typedData: DocTypedData
}

public enum DocElements: Identifiable, Sendable {
	case msoMdoc(MsoMdocElements)
	case sdJwt(SdJwtElements)
	case w3cJwt(W3CJwtElements)

	public var id: String {
	 switch self {
	 case .msoMdoc(let element): return element.id
	 case .sdJwt(let element): return element.id
	 case .w3cJwt(let e):  return e.id
	 }
	}

	public var msoMdoc: MsoMdocElements? {
		if case .msoMdoc(let mdoc) = self { return mdoc } else { return nil }
	}
	public var sdJwt: SdJwtElements? {
		if case .sdJwt(let sd) = self { return sd } else { return nil }
	}
	public var w3cJwt: W3CJwtElements? {
		if case .w3cJwt(let w3c) = self { return w3c } else { return nil }
	}

	public var isMsoMdoc: Bool {
		if case .msoMdoc(_) = self { return true } else { return false }
	}
	public var isSdJwt: Bool {
		if case .sdJwt(_) = self { return true } else { return false }
	}
	public var isW3CJwt: Bool {
		if case .w3cJwt(_) = self { return true } else { return false }
	}
	public var docTypeOrVct: String {
		switch self {
		case .msoMdoc(let mdoc): return mdoc.docType
		case .sdJwt(let sdJwt): return sdJwt.vct
		case .w3cJwt(let w3cJwt): return w3cJwt.types.last ?? ""
		}
	}
	public var isValid: Bool {
		switch self {
		case .msoMdoc(let mdoc): return mdoc.isValid
		case .sdJwt(let sdJwt): return sdJwt.isValid
		case .w3cJwt(let w3cJwt): return w3cJwt.isValid
		}
	}
	public var docId: String {
		switch self {
		case .msoMdoc(let mdoc): return mdoc.docId
		case .sdJwt(let sdJwt): return sdJwt.docId
		case .w3cJwt(let w3cJwt): return w3cJwt.docId
		}
	}
	public var selectedItemsDictionary: [String: [RequestItem]] {
		switch self {
		case .msoMdoc(let mdoc): return mdoc.selectedItemsDictionary
		case .sdJwt(let sdJwt): return sdJwt.selectedItemsDictionary
		case .w3cJwt(let w3cJwt): return w3cJwt.selectedItemsDictionary
		}
	}
}

/// Element collection for mso-mdoc document
/// Used for disclosure of mdoc elements
public final class MsoMdocElements: Identifiable, @unchecked Sendable {
	public init(docId: String, docType: String, displayName: String? = nil, isValid: Bool = true, nameSpacedElements: [NameSpacedElements]) {
		self.docId = docId
		self.docType = docType
		self.displayName = displayName
		self.isValid = isValid
		self.nameSpacedElements = nameSpacedElements
	}

	public var id: String { docId }
	/// Document identifier
	public var docId: String
	/// Document type
	public let docType: String
	/// Display name of the document
	public let displayName: String?
	/// Indicates whether the document is enabled (false if requested but not available)
	public var isValid: Bool = true
	/// Collection of elements grouped by namespace
	public var nameSpacedElements: [NameSpacedElements]
	/// Dictionary of selected items grouped by namespace
	public var selectedItemsDictionary: [String: [RequestItem]] {
		Dictionary(grouping: nameSpacedElements, by: \.nameSpace).filter { $1.first!.elements.count > 0}.mapValues {ne in ne.first!.elements.filter(\.isValidAndSelected).map(\.requestItem)}
	}
}

public final class SdJwtElements: Identifiable, @unchecked Sendable {
	public init(docId: String, vct: String, displayName: String? = nil, isValid: Bool = true, sdJwtElements: [SdJwtElement]) {
		self.docId = docId
		self.vct = vct
		self.displayName = displayName
		self.isValid = isValid
		self.sdJwtElements = sdJwtElements
	}

	public var id: String { docId }
	public var docId: String
	public let vct: String
	public let displayName: String?
	public var isValid: Bool = true
	public var sdJwtElements: [SdJwtElement]

	public var selectedItemsDictionary: [String: [RequestItem]] {
		["": sdJwtElements.filter(\.isValidAndSelected).flatMap(\.selectedRequestItems)]
	}
}

/// Element collection for a W3C JWT-VC credential.
/// Unlike SD-JWT, JWT-VC has no selective disclosure — all claims in `credentialSubject` are plaintext.
/// The `types` array mirrors the `type` field in the JWT payload (e.g. `["VerifiableCredential", "UniversityDegreeCredential"]`).
public final class W3CJwtElements: Identifiable, @unchecked Sendable {
	public init(docId: String, types: [String], displayName: String? = nil, isValid: Bool = true, elements: [SdJwtElement]) {
		self.docId = docId
		self.types = types
		self.displayName = displayName
		self.isValid = isValid
		self.elements = elements
	}

	public var id: String { docId }
	public var docId: String
	/// Full type array from the JWT `type` field, e.g. ["VerifiableCredential", "UniversityDegreeCredential"]
	public let types: [String]
	public let displayName: String?
	public var isValid: Bool = true
	public var elements: [SdJwtElement]

	public var selectedItemsDictionary: [String: [RequestItem]] {
		["": elements.filter(\.isValidAndSelected).flatMap(\.selectedRequestItems)]
	}
}

extension IssuerSigned {
	public func extractMsoMdocElements(docId: String, docType: String, displayName: String?, docClaims: [DocClaim], itemsRequested: [NameSpace: [RequestItem]]) -> MsoMdocElements {
		let itemsReq = if itemsRequested.count > 0 { itemsRequested } else { Dictionary(grouping: docClaims, by: { $0.path.first! }).mapValues { $0.map { RequestItem(elementPath: Array($0.path.dropFirst())) } } }
		return MsoMdocElements(docId: docId, docType: docType, displayName: displayName, nameSpacedElements: itemsReq.compactMap { ns, requestItems in
			extractNameSpacedElements(docType: docType, ns: ns, docClaims: docClaims, requestItems: requestItems)
		})
	}

	public func extractNameSpacedElements(docType: String, ns: String, docClaims: [DocClaim], requestItems: [RequestItem]) -> NameSpacedElements? {
		guard let issuedItems = issuerNameSpaces?[ns] else { return nil }
		let mandatoryElementKeys = MsoMdocElements.getMandatoryElementKeys(docType: docType, ns: ns)
		let isMandatory: (RequestItem) -> Bool = { if let o = $0.isOptional { !o } else { mandatoryElementKeys.contains($0.rootIdentifier) } }
		return NameSpacedElements(nameSpace: ns, elements: requestItems.map { $0.extractMsoMdocElement(ns: ns, nsItems: issuedItems, docClaims: docClaims, isMandatory: isMandatory($0)) })
	}
}

extension SignedSDJWT {
	public func extractSdJwtElements(docId: String, vct: String, displayName: String?, docClaims: [DocClaim], itemsRequested: [NameSpace: [RequestItem]]) -> SdJwtElements? {
		guard let allPathsDict = (try? recreateClaims())?.disclosuresPerClaimPath else { return nil }
		let allPaths = OrderedSet(allPathsDict.keys).union(docClaims.flatMap(\.claimPaths))
		let isMandatory: (RequestItem) -> Bool = { if let o = $0.isOptional { !o } else { false } }
		let itemsReq = itemsRequested[""] ?? allPaths.map { RequestItem(elementPath: $0.value.map(\.claimName)) }
		var sdJwtArray = [SdJwtElement]()
		let tmp = itemsReq.map { reqItem in reqItem.extractSdJwtElement(allPaths: allPaths, docClaims: docClaims, isMandatory: isMandatory(reqItem), bRootOnly: true) }
		for d in tmp { if !sdJwtArray.contains(d) { sdJwtArray.append(d) } }
		for nestedReqItem in itemsReq.filter({ $0.elementPath.count > 1 }) {
			let parentSd = sdJwtArray.first(where: { $0.elementPath == [nestedReqItem.rootIdentifier] })!
			let nestedSd = nestedReqItem.extractSdJwtElement(allPaths: allPaths, docClaims: docClaims, isMandatory: isMandatory(nestedReqItem), bRootOnly: false)
			if parentSd.nestedElements == nil { parentSd.nestedElements = [] }
			parentSd.nestedElements!.append(nestedSd)
		}
		return SdJwtElements(docId: docId, vct: vct, displayName: displayName, sdJwtElements: sdJwtArray)
	}
}

extension eudi_lib_sdjwt_swift.ClaimPathElement {
	public var claimName: String {
		if case .claim(let name) = self { name } else if case .arrayElement(let index) = self { String(index) } else { "" }
	}
}

extension RequestItem {

	public var claimPath: ClaimPath {
		ClaimPath(elementPath.map { if let index = Int($0) { ClaimPathElement.arrayElement(index: index) } else if $0.isEmpty { ClaimPathElement.allArrayElements } else { ClaimPathElement.claim(name: $0) } })
	}

	public func extractMsoMdocElement(ns: String, nsItems: [IssuerSignedItem], docClaims: [DocClaim], isMandatory: Bool) -> MsoMdocElement {
		let issuedElement = nsItems.first { $0.elementIdentifier == rootIdentifier }
		let stringValue = issuedElement?.description
		let docClaim = docClaims.first { $0.namespace == ns && $0.name == rootIdentifier }
		return MsoMdocElement(elementIdentifier: elementIdentifier, isOptional: !isMandatory, intentToRetain: intentToRetain ?? false, stringValue: stringValue, docClaim: docClaim, isValid: issuedElement != nil)
	}

	public func extractSdJwtElement(allPaths: OrderedSet<ClaimPath>, docClaims: [DocClaim], isMandatory: Bool, bRootOnly: Bool) -> SdJwtElement {
		// find path that the request item contains it
		let requestClaimPath = claimPath
		let query = allPaths.first { path in path == requestClaimPath } ?? allPaths.first { path in requestClaimPath.contains2(path) }
		let isValid = query != nil
		let requestPath = bRootOnly ? [rootIdentifier] : elementPath
		let docClaim: DocClaim? = findDocClaimByPath(docClaims: docClaims, requestPath: requestPath)
		let stringValue: String? = docClaim?.stringValue
		return SdJwtElement(elementPath: requestPath, isOptional: !isMandatory, intentToRetain: intentToRetain ?? false, stringValue: stringValue, docClaim: docClaim, isValid: isValid, nestedElements: nil)
	}

	public func findDocClaimByPath(docClaims: [DocClaim], requestPath: [String]) -> DocClaim? {
		var res: DocClaim? = docClaims.first { $0.path == requestPath }
		if res != nil { return res }
		var docClaimsArray: [DocClaim]? = docClaims
		for i in requestPath.indices {
			guard docClaimsArray != nil else { return nil }
			guard let c = RequestItem.findDocClaimByName(docClaimsArray!, name: requestPath[i]) else { return nil }
			res = c; docClaimsArray = c.children
		}
		return res
	}

	static func findDocClaimByName(_ docClaims: [DocClaim], name: String) -> DocClaim? {
		docClaims.first { $0.name == name }
	}
}

extension String {
	/// Extracts W3C JWT-VC claims from a raw JWT string.
	/// JWT-VC stores all claims in plaintext under `vc.credentialSubject` — no selective disclosure.
	/// `itemsRequested` uses the empty-string namespace key (`""`) with dot-notation paths into `credentialSubject`.
	/// `fallbackDocType` is used as the sole entry in `types` when the JWT payload does not contain a `type` array.
	public func extractW3CJwtElements(docId: String, fallbackDocType: String, displayName: String?, docClaims: [DocClaim], itemsRequested: [NameSpace: [RequestItem]]) -> W3CJwtElements? {
		// Decode the JWT payload (second Base64URL segment)
		let parts = split(separator: ".", omittingEmptySubsequences: false)
		guard parts.count >= 2,
			  let payloadData = Data(base64URLEncoded: String(parts[1])),
			  let payload = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else { return nil }
		// Extract the type array from `vc.type` (JWT-VC spec) or fall back to the stored docType string
		let vcObject = payload["vc"] as? [String: Any]
		let types = vcObject?["type"] as? [String] ?? [fallbackDocType]
		// Claims live under `vc.credentialSubject` (JWT-VC) or directly in `credentialSubject` (some issuers)
		let credentialSubject = vcObject?["credentialSubject"] as? [String: Any]
			?? payload["credentialSubject"] as? [String: Any]
			?? [:]
		let allPaths = OrderedSet(docClaims.flatMap(\.claimPaths))
		let isMandatory: (RequestItem) -> Bool = { if let o = $0.isOptional { !o } else { false } }
		let itemsReq = itemsRequested[""] ?? allPaths.map { RequestItem(elementPath: $0.value.map(\.claimName)) }
		var elements = itemsReq.map { reqItem -> SdJwtElement in
			let requestPath = reqItem.elementPath
			let docClaim: DocClaim? = reqItem.findDocClaimByPath(docClaims: docClaims, requestPath: requestPath)
			// Walk the credentialSubject dict to find the value at the claim path
			var node: Any? = credentialSubject
			for key in requestPath { node = (node as? [String: Any])?[key] }
			let stringValue = node.map { "\($0)" } ?? docClaim?.stringValue
			let isValid = node != nil
			return SdJwtElement(elementPath: requestPath, isOptional: !isMandatory(reqItem), intentToRetain: reqItem.intentToRetain ?? false, stringValue: stringValue, docClaim: docClaim, isValid: isValid, nestedElements: nil)
		}
		// De-duplicate root elements and attach nested children (mirrors SD-JWT logic)
		var rootElements = [SdJwtElement]()
		for el in elements where el.elementPath.count == 1 { if !rootElements.contains(el) { rootElements.append(el) } }
		for nested in elements.filter({ $0.elementPath.count > 1 }) {
			guard let parent = rootElements.first(where: { $0.elementPath == [nested.elementPath[0]] }) else { continue }
			if parent.nestedElements == nil { parent.nestedElements = [] }
			parent.nestedElements!.append(nested)
		}
		return W3CJwtElements(docId: docId, types: types, displayName: displayName, elements: rootElements)
	}
}

extension MsoMdocElements {

	static func getMandatoryElementKeys(docType: String, ns: String) -> [String] {
		switch (docType, ns) {
		case (IsoMdlModel.isoDocType, IsoMdlModel.isoNamespace):
			return IsoMdlModel.isoMandatoryElementKeys
		case (EuPidModel.euPidDocType, "eu.europa.ec.eudi.pid.1"):
			return EuPidModel.pidMandatoryElementKeys
		default:
			return []
		}
	}
}

extension Array where Element == DocElements {
	public var items: RequestItems { Dictionary(grouping: self, by: \.docId).mapValues { $0.first!.selectedItemsDictionary } }
}

extension ClaimPath {
 	public func contains2(_ that: ClaimPath) -> Bool { zip(self.value, that.value).allSatisfy { (selfElement, thatElement) in selfElement.contains(thatElement) } }
}

public final class NameSpacedElements: Identifiable, @unchecked Sendable {
	public init(nameSpace: String, elements: [MsoMdocElement]) {
		self.nameSpace = nameSpace
		self.elements = elements
	}
	public var id: String { nameSpace }
	public let nameSpace: String
	public var elements: [MsoMdocElement]
}

public final class MsoMdocElement: Identifiable, ObservableObject, @unchecked Sendable {
	public init(elementIdentifier: String, isOptional: Bool, intentToRetain: Bool = false, stringValue: String?, docClaim: DocClaim?, isValid: Bool, isSelected: Bool = true) {
		self.elementIdentifier = elementIdentifier
		self.isOptional = isOptional
		self.intentToRetain = intentToRetain
		self.stringValue = stringValue
		self.docClaim = docClaim
		self.isValid = isValid
		self.isSelected = isSelected
	}

	public var id: String { elementIdentifier }
	/// path to locate the element
	public let elementIdentifier: String
	public let isOptional: Bool
	public var intentToRetain: Bool = false
	public let stringValue: String?
	public let docClaim: DocClaim?
	@Published public var isValid: Bool
	@Published public var isSelected = true
	public var isValidAndSelected: Bool { isValid && isSelected }

	public var requestItem: RequestItem {
		RequestItem(elementPath: [elementIdentifier], intentToRetain: intentToRetain, isOptional: isOptional)
	}
}

public final class SdJwtElement: Identifiable, ObservableObject, @unchecked Sendable, Hashable {
	public init(elementPath: [String], isOptional: Bool, intentToRetain: Bool = false, stringValue: String?, docClaim: DocClaim?, isValid: Bool, isSelected: Bool = true, nestedElements: [SdJwtElement]? = nil) {
		self.elementPath = elementPath
		self.isOptional = isOptional
		self.intentToRetain = intentToRetain
		self.stringValue = stringValue
		self.docClaim = docClaim
		self.isValid = isValid
		self.isSelected = isSelected
		self.nestedElements = nestedElements
	}

	public var id: String { elementPath.joined(separator: ".") }
	/// path to locate the element
	public let elementPath: [String]
	public let isOptional: Bool
	public let intentToRetain: Bool
	public let stringValue: String?
	public let docClaim: DocClaim?
	@Published public var isValid: Bool
	@Published public var isSelected = true
	public var isValidAndSelected: Bool { isValid && isSelected }
	public var nestedElements: [SdJwtElement]?

	public var requestItem: RequestItem {
		RequestItem(elementPath: elementPath, intentToRetain: intentToRetain, isOptional: isOptional)
	}
	public var selectedRequestItems: [RequestItem] {
		[requestItem] + (nestedElements?.filter(\.isValidAndSelected).flatMap(\.selectedRequestItems) ?? [])
	}

	public static func == (lhs: SdJwtElement, rhs: SdJwtElement) -> Bool { lhs.elementPath == rhs.elementPath }

	public func hash(into hasher: inout Hasher) {
		hasher.combine(id.hashValue)
	}
}


