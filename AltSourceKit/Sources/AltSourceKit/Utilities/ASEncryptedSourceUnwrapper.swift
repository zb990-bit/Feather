//
//  ASEncryptedSourceUnwrapper.swift
//  AltSourceKit
//
//  Unwraps NSKSign-compatible encrypted software sources:
//  - plain JSON
//  - {"appstore": "..."}      Base64 + RC4 (remote RC4 key)
//  - {"appstore_v1": "..."}   Base64 + chunked RSA PKCS#1 v1.5
//  - appstore_v2 is intentionally unsupported (no verified sample)
//

import Foundation
import Security

public enum ASEncryptedSourceError: Error, LocalizedError, Sendable {
	case invalidJSON
	case unsupportedV2
	case invalidBase64
	case invalidKey
	case rsaFailed
	case remoteKeyFailed
	case decryptedJSONInvalid

	public var errorDescription: String? {
		switch self {
		case .invalidJSON: "软件源外层 JSON 无效。"
		case .unsupportedV2: "暂不支持 appstore_v2：当前尚无可验证的真实样本。"
		case .invalidBase64: "软件源密文 Base64 无效。"
		case .invalidKey: "软件源解密密钥无效。"
		case .rsaFailed: "软件源 RSA 解密失败。"
		case .remoteKeyFailed: "获取软件源解密配置失败，请检查网络后重试。"
		case .decryptedJSONInvalid: "软件源数据解密失败或内容格式无效。"
		}
	}
}

public enum ASEncryptedSourceUnwrapper {
	static let updateURL = URL(string: "https://api.nuosike.com/update.json")!
	static let keyURL = URL(string: "https://api.nuosike.com/key.json")!

	/// Returns plaintext UTF-8 JSON data suitable for `ASRepository` decoding.
	public static func unwrap(_ data: Data) async throws -> Data {
		guard
			let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
		else {
			throw ASEncryptedSourceError.invalidJSON
		}

		if object["appstore_v2"] != nil {
			throw ASEncryptedSourceError.unsupportedV2
		}

		if let cipherText = object["appstore_v1"] as? String {
			return try decryptV1(cipherText)
		}

		if let cipherText = object["appstore"] as? String {
			do {
				return try await decryptLegacyAppStore(cipherText, forceRefreshKeys: false)
			} catch {
				return try await decryptLegacyAppStore(cipherText, forceRefreshKeys: true)
			}
		}

		return data
	}

	private static func decryptLegacyAppStore(
		_ cipherText: String,
		forceRefreshKeys: Bool
	) async throws -> Data {
		let rc4Key = try await ASLegacyAppStoreKeyStore.shared.rc4Key(forceRefresh: forceRefreshKeys)
		guard let cipherData = Data(base64Encoded: cipherText, options: [.ignoreUnknownCharacters]) else {
			throw ASEncryptedSourceError.invalidBase64
		}
		let plain = try rc4(data: cipherData, key: rc4Key)
		guard
			let text = String(data: plain, encoding: .utf8),
			let normalized = text.data(using: .utf8),
			(try? JSONSerialization.jsonObject(with: normalized)) != nil
		else {
			throw ASEncryptedSourceError.decryptedJSONInvalid
		}
		return normalized
	}

	private static func decryptV1(_ cipherText: String) throws -> Data {
		guard let cipherData = Data(base64Encoded: cipherText, options: [.ignoreUnknownCharacters]) else {
			throw ASEncryptedSourceError.invalidBase64
		}

		let privateKey = try importRSAPrivateKey(pem: ASAppStoreV1PrivateKey.pem)
		let blockSize = SecKeyGetBlockSize(privateKey)
		guard blockSize > 0, cipherData.count % blockSize == 0 else {
			throw ASEncryptedSourceError.rsaFailed
		}

		var output = Data()
		output.reserveCapacity(cipherData.count)

		var offset = 0
		while offset < cipherData.count {
			let block = cipherData.subdata(in: offset..<(offset + blockSize))
			output.append(try rsaDecrypt(block, privateKey: privateKey))
			offset += blockSize
		}

		guard
			let text = String(data: output, encoding: .utf8),
			let normalized = text.data(using: .utf8),
			(try? JSONSerialization.jsonObject(with: normalized)) != nil
		else {
			throw ASEncryptedSourceError.decryptedJSONInvalid
		}
		return normalized
	}
}

// MARK: - Remote key cache

actor ASLegacyAppStoreKeyStore {
	static let shared = ASLegacyAppStoreKeyStore()

	private var cachedRC4Key: Data?

	func rc4Key(forceRefresh: Bool) async throws -> Data {
		if !forceRefresh, let cachedRC4Key {
			return cachedRC4Key
		}

		let updateData = try await Self.fetchData(from: ASEncryptedSourceUnwrapper.updateURL)
		let keyData = try await Self.fetchData(from: ASEncryptedSourceUnwrapper.keyURL)

		guard
			let updateJSON = try JSONSerialization.jsonObject(with: updateData) as? [String: Any],
			let keyJSON = try JSONSerialization.jsonObject(with: keyData) as? [String: Any],
			let akeyB64 = updateJSON["rule"] as? String,
			let bkeyB64 = keyJSON["rule"] as? String,
			let akeyPEMData = Data(base64Encoded: akeyB64, options: [.ignoreUnknownCharacters]),
			let akeyPEM = String(data: akeyPEMData, encoding: .utf8),
			let encryptedKey = Data(base64Encoded: bkeyB64, options: [.ignoreUnknownCharacters])
		else {
			throw ASEncryptedSourceError.remoteKeyFailed
		}

		let privateKey = try importRSAPrivateKey(pem: akeyPEM)
		let rc4Key = try rsaDecrypt(encryptedKey, privateKey: privateKey)
		guard !rc4Key.isEmpty else { throw ASEncryptedSourceError.invalidKey }
		cachedRC4Key = rc4Key
		return rc4Key
	}

	private static func fetchData(from url: URL) async throws -> Data {
		let (data, response) = try await URLSession.shared.data(from: url)
		guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
			throw ASEncryptedSourceError.remoteKeyFailed
		}
		return data
	}
}

// MARK: - Crypto helpers

func importRSAPrivateKey(pem: String) throws -> SecKey {
	guard let der = pemToDER(pem) else {
		throw ASEncryptedSourceError.invalidKey
	}

	let attributes: [String: Any] = [
		kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
		kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
	]

	var error: Unmanaged<CFError>?
	guard let key = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, &error) else {
		throw ASEncryptedSourceError.invalidKey
	}
	return key
}

func rsaDecrypt(_ data: Data, privateKey: SecKey) throws -> Data {
	var error: Unmanaged<CFError>?
	guard let plain = SecKeyCreateDecryptedData(
		privateKey,
		.rsaEncryptionPKCS1,
		data as CFData,
		&error
	) as Data? else {
		throw ASEncryptedSourceError.rsaFailed
	}
	return plain
}

func pemToDER(_ pem: String) -> Data? {
	let lines = pem
		.components(separatedBy: .newlines)
		.filter { !$0.hasPrefix("-----") && !$0.isEmpty }
	return Data(base64Encoded: lines.joined(), options: [.ignoreUnknownCharacters])
}

func rc4(data: Data, key: Data) throws -> Data {
	guard !key.isEmpty else { throw ASEncryptedSourceError.invalidKey }

	var state = Array(UInt8(0)...UInt8(255))
	var j = 0
	for i in 0..<256 {
		j = (j + Int(state[i]) + Int(key[i % key.count])) & 0xff
		state.swapAt(i, j)
	}

	var i = 0
	j = 0
	var output = Data(count: data.count)
	for (offset, byte) in data.enumerated() {
		i = (i + 1) & 0xff
		j = (j + Int(state[i])) & 0xff
		state.swapAt(i, j)
		let streamByte = state[(Int(state[i]) + Int(state[j])) & 0xff]
		output[offset] = byte ^ streamByte
	}
	return output
}

// MARK: - Repository fetch helper

public enum ASRepositoryLoader {
	public static func load(from url: URL) async throws -> ASRepository {
		let (data, response) = try await URLSession.shared.data(from: url)
		if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
			throw URLError(.badServerResponse)
		}
		let plain = try await ASEncryptedSourceUnwrapper.unwrap(data)
		return try JSONDecoder().decode(ASRepository.self, from: plain)
	}

	public static func load(
		from url: URL,
		completion: @escaping (Result<ASRepository, Error>) -> Void
	) {
		Task.detached {
			do {
				let repo = try await load(from: url)
				completion(.success(repo))
			} catch {
				completion(.failure(error))
			}
		}
	}
}
