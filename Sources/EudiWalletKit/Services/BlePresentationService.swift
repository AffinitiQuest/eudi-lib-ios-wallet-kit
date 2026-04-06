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
import MdocDataModel18013
import MdocDataTransfer18013
import MdocSecurity18013

/// Implements proximity attestation presentation with QR to BLE data transfer

/// Implementation is based on the ISO/IEC 18013-5 specification

public final class BlePresentationService: @unchecked Sendable, PresentationService {
	var bleServerTransfer: MdocGattServer
	public var status: TransferStatus = .initializing
	var continuationRequest: CheckedContinuation<UserRequestInfo, Error>?
	var handleSelected: ((Bool, RequestItems?) async -> Void)?
	var deviceEngagement: String?
	var request: UserRequestInfo?
	public var transactionLog: TransactionLog
	public var flow: FlowType { .ble }

	public init(parameters: InitializeTransferData) throws {
		bleServerTransfer = try MdocGattServer(parameters: parameters)
		transactionLog = TransactionLogUtils.initializeTransactionLog(type: .presentation, dataFormat: .cbor)
		bleServerTransfer.delegate = self
		bleServerTransfer.ldpVcVPGenerator = { [weak bleServerTransfer] docId, credentialJson, nonce in
			guard let bleServerTransfer else { throw NSError(domain: "BlePresentation", code: 0, userInfo: [NSLocalizedDescriptionKey: "BLE server deallocated"]) }
			guard let dpk = bleServerTransfer.privateKeyObjects[docId] else {
				throw NSError(domain: "BlePresentation", code: 1, userInfo: [NSLocalizedDescriptionKey: "No private key for docId: \(docId)"])
			}
			let unlockData = bleServerTransfer.unlockData?[docId]
			let keyInfo = try await dpk.secureArea.getKeyBatchInfo(id: docId)
			let dsa = keyInfo.crv.defaultSigningAlgorithm
			let signer = try SecureAreaSigner(secureArea: dpk.secureArea, id: docId, index: dpk.index, ecAlgorithm: dsa, unlockData: unlockData)
			let publicKey = try await dpk.secureArea.getPublicKey(id: docId, index: dpk.index, curve: .P256)
			let holderDid = OpenId4VpUtils.holderDidFromCoseKey(publicKey)
			guard let vpJson = try await OpenId4VpUtils.getLdpVcPresentation(credentialJson, signer: signer, nonce: nonce, aud: "ble", holderDid: holderDid) else {
				throw NSError(domain: "BlePresentation", code: 2, userInfo: [NSLocalizedDescriptionKey: "Failed to generate LDP-VC VP"])
			}
			return vpJson
		}
	}

	/// Generate device engagement QR code

	/// The holder app should present the returned code to the verifier
	/// - Returns: The image data for the QR code
	public func startQrEngagement(secureAreaName: String?, crv: CoseEcCurve) async throws -> String {
		if bleServerTransfer.unlockData == nil {
			var unlockData = [String: Data]()
			for (id, key) in bleServerTransfer.privateKeyObjects {
				let ud = try await key.secureArea.unlockKey(id: id)
				if let ud { unlockData[id] = ud }
			}
			bleServerTransfer.unlockData = unlockData
		}
		try await self.bleServerTransfer.performDeviceEngagement(secureArea: SecureAreaRegistry.shared.get(name: secureAreaName), crv: crv)
		return self.bleServerTransfer.status == .qrEngagementReady ? self.bleServerTransfer.qrCodePayload! : ""
	}

	///  Receive request via BLE
	///
	/// - Returns: The requested items.
	public func receiveRequest() async throws -> UserRequestInfo {
		let userRequestInfo = try await withCheckedThrowingContinuation { c in
			continuationRequest = c
		}
		TransactionLogUtils.setCborTransactionLogRequestInfo(userRequestInfo, transactionLog: &transactionLog)
		return userRequestInfo
	}

	public func unlockKey(id: String) async throws -> Data? {
		if let dpo = bleServerTransfer.privateKeyObjects[id] {
			return try await dpo.secureArea.unlockKey(id: id)
		}
		return nil
	}
	/// Send response via BLE
	///
	/// - Parameters:
	///   - userAccepted: True if user accepted to send the response
	///   - itemsToSend: The selected items to send organized in document types and namespaces
	public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, onSuccess: (@Sendable (URL?) -> Void)?) async throws  {
		await handleSelected?(userAccepted, itemsToSend)
		handleSelected = nil
		TransactionLogUtils.setCborTransactionLogResponseInfo(bleServerTransfer, transactionLog: &transactionLog)
	}
}

/// handle events from underlying BLE service
extension BlePresentationService: MdocOfflineDelegate {
	/// BLE transfer changed status
	/// - Parameter newStatus: New status
	public func didChangeStatus(_ newStatus: MdocDataTransfer18013.TransferStatus) {
		status = if let st = TransferStatus(rawValue: newStatus.rawValue) { st } else { .error }
		switch newStatus {
		case .qrEngagementReady:
			if let qrCode = self.bleServerTransfer.qrCodePayload { deviceEngagement = qrCode }
		default: break
		}
	}
	/// Transfer finished with error
	/// - Parameter error: The error description
	public func didFinishedWithError(_ error: Error) {
		continuationRequest?.resume(throwing: error); continuationRequest = nil
	}

	/// Received request handler
	/// - Parameters:
	///   - request: Request information
	///   - handleSelected: Callback function to call after user selection of items to send
	public func didReceiveRequest(_ request: UserRequestInfo, handleSelected: @escaping (Bool, MdocDataTransfer18013.RequestItems?) async -> Void) {
		self.handleSelected = handleSelected
		self.request = request
		continuationRequest?.resume(returning: request)
		continuationRequest = nil
	}

}
