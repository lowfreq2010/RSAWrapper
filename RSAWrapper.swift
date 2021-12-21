// swiftlint:disable force_cast
import Foundation
import Security

class RSAWrapper: NSObject {

    enum RSAKeyLength: Int {
        case RSA512 = 512
        case RSA1024 = 1024
        case RSA2048 = 2048
		case RSA4096 = 4096
    }

    enum RSAErrors: Error {
        case nilKey
        case wrongKeyLength
        case noKeyOnKeychain
        case nilPublicKey
        case nilExternalRepresentation
        case nilCiphertext
        case nilPlaintext
        case notsupportedCryptoAlgo
        case privateKeyCannotDecrypt
		case noX509certificate
    }

    private var publicKey: SecKey?
    private var privateKey: SecKey?
	private var importedPublicKey: SecKey?
    private var generatedPair: SecKey?
    private let algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1

    var error: Unmanaged<CFError>?

    convenience init(with keySize: RSAKeyLength, privateTag: String) throws {
        self.init()
        let storedKey: SecKey? = loadKey(name: privateTag)
        if storedKey == nil {
            try generateKeyPair(keySize: keySize, privateTag: privateTag)
        }
        try createPrivateKey(with: privateTag)
        try createPublicKey()
    }
	
	convenience init(with derFilePath: String) throws {
		self.init()
        importedPublicKey = importPublicKeyReferenceFromDER(derFilePath)
	}

    private func loadKey(name: String) -> SecKey? {
        let tag = name.data(using: .utf8) ?? Data()
        let query: [String: Any] = [
            kSecClass as String                 : kSecClassKey,
            kSecAttrApplicationTag as String    : tag,
            kSecAttrKeyType as String           : kSecAttrKeyTypeRSA,
            kSecReturnRef as String             : true,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            return nil
        }
        if let item = item {
            return (item as! SecKey)
        }
        return nil
    }

    private func generateKeyPair(keySize: RSAKeyLength, privateTag: String) throws {

        generatedPair = nil
        let attributes: CFDictionary =
            [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits as String: keySize.rawValue,
                kSecPrivateKeyAttrs as String:
                    [
                        kSecAttrIsPermanent as String: true,
                        kSecAttrApplicationTag as String: privateTag,
                    ],
            ] as CFDictionary

        guard let generated = SecKeyCreateRandomKey(attributes, &error) else {
            throw RSAErrors.nilKey
        }
        generatedPair = generated
    }

    private func createPrivateKey(with tag: String) throws {

        var secItem: CFTypeRef?

        privateKey = nil
        let query: CFDictionary = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnRef as String: true,
        ] as CFDictionary

        let status = SecItemCopyMatching(query, &secItem)
        guard status == errSecSuccess else {
            throw RSAErrors.noKeyOnKeychain
        }
        privateKey = (secItem as! SecKey)
    }

    private func createPublicKey() throws {

        publicKey = nil
        guard let privateKey = privateKey else {
            throw RSAErrors.nilKey
        }
        guard let generatedPK = SecKeyCopyPublicKey(privateKey) else {
            throw RSAErrors.nilKey
        }
        publicKey = generatedPK
        guard SecKeyIsAlgorithmSupported(generatedPK, .encrypt, .rsaEncryptionPKCS1) else {
            throw RSAErrors.notsupportedCryptoAlgo
        }

    }
	
	/**
	 * Extracts the public key from a X.509 certificate and returns a valid SecKeyRef that can be
	 * used in any of SecKey operations (SecKeyEncrypt, SecKeyRawVerify...).
	 * Receives the certificate data in DER format.
	 */
	private func importPublicKeyReferenceFromDER(_ certData: Data) -> SecKey? {
		// first we create the certificate reference
		guard let certRef = SecCertificateCreateWithData(nil, certData as CFData) else { return nil }
		print("Successfully generated a valid certificate reference from the data.")
		
		// now create a SecTrust structure from the certificate where to extract the key from
		var secTrust: SecTrust?
		let secTrustStatus = SecTrustCreateWithCertificates(certRef, nil, &secTrust)
		print("Generating a SecTrust reference from the certificate: \(secTrustStatus)")
		if secTrustStatus != errSecSuccess { return nil }
		
		// now evaluate the certificate.
		var resultType: SecTrustResultType = SecTrustResultType(rawValue: UInt32(0))! // result will be ignored.
		let evaluateStatus = SecTrustEvaluate(secTrust!, &resultType)
		print("Evaluating the obtained SecTrust reference: \(evaluateStatus)")
		if evaluateStatus != errSecSuccess { return nil }
		
		// lastly, once evaluated, we can export the public key from the certificate leaf.
		let publicKeyRef = SecTrustCopyPublicKey(secTrust!)
		print("Got public key reference: \(String(describing: publicKeyRef))")
		return publicKeyRef
	}
	
	public func importPublicKey(from derFilePath: String) throws -> SecKey? {
		guard let certData = try? Data(contentsOf: URL(fileURLWithPath: certPath)) else {
			throw RSAErrors.noX509certificate
		}
		return importPublicKeyReferenceFromDER(certData)
	}

    public func publicKeyAsPEM() throws -> String {
        // client public key to pem string
        guard let publicKey = publicKey else {
            throw RSAErrors.nilPublicKey
        }
        let keyData = SecKeyCopyExternalRepresentation(publicKey, &error)
        let data = keyData! as Data
        let pemPrefixBuffer :[UInt8] = [
            0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a,
            0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
            0x05, 0x00, 0x03, 0x81, 0x8d, 0x00,
        ]
        var finalPemData = Data(bytes: pemPrefixBuffer as [UInt8], count: pemPrefixBuffer.count)
        finalPemData.append(data)
        let finalPemString = finalPemData.base64EncodedString(options: .lineLength64Characters)
        let clientPublicKeyString = "-----BEGIN PUBLIC KEY-----\r\n\(finalPemString)\r\n-----END PUBLIC KEY-----\r\n"
        print(clientPublicKeyString)
        return clientPublicKeyString
    }

    public func publicKeyAsBase64() throws -> String {
        guard let publicKey = publicKey else {
            throw RSAErrors.nilPublicKey
        }
        guard let publicKeyExportable = SecKeyCopyExternalRepresentation(publicKey, nil) else {
            throw RSAErrors.nilPublicKey
        }
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
            throw RSAErrors.notsupportedCryptoAlgo
        }

        return (publicKeyExportable as Data).base64EncodedString()
    }

    public func encrypt(text: String) throws -> [UInt8] {

        guard let textToEncryptData = text.data(using: .utf8) else {
            throw RSAErrors.nilCiphertext
        }
        guard let publicKey = publicKey, let privateKey = privateKey else {
            throw RSAErrors.nilKey
        }
        guard let cipherText = SecKeyCreateEncryptedData(
            publicKey,
            algorithm,
            textToEncryptData as CFData,
            &error) as Data? else
        {
            throw RSAErrors.nilCiphertext
        }
        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
            throw RSAErrors.notsupportedCryptoAlgo
        }

        guard cipherText.count == SecKeyGetBlockSize(privateKey) else {
            throw RSAErrors.nilCiphertext
        }
        return [UInt8](cipherText)
    }

    public func decrypt(encrypted: [UInt8]) throws -> String? {

        guard let privateKey = privateKey else {
            throw RSAErrors.nilKey
        }

        let cipherData = Data(encrypted) as CFData
        guard let clearTextData = SecKeyCreateDecryptedData(
            privateKey,
            algorithm,
            cipherData,
            &error) as Data? else
        {
            throw RSAErrors.privateKeyCannotDecrypt
        }

        guard let clearText = String(data: clearTextData, encoding: .utf8) else {
            throw RSAErrors.privateKeyCannotDecrypt
        }
        return clearText
    }

    public func encryptBase64(text: String) throws -> String {
        let encryptedText = try encrypt(text: text)
        let encryptedData = NSData(data: Data(encryptedText))
        return encryptedData.base64EncodedString(options: NSData.Base64EncodingOptions.lineLength64Characters)
    }

    public func decryptBase64(encryptedBase64: String) throws -> String? {

        let data: NSData = NSData(base64Encoded: encryptedBase64, options: .ignoreUnknownCharacters) ?? NSData()
        let count = data.length / MemoryLayout<UInt8>.size
        var array = [UInt8](repeating: 0, count: count)
        data.getBytes(&array, length:count * MemoryLayout<UInt8>.size)
        guard let clearText = try decrypt(encrypted: array) else {
            throw RSAErrors.privateKeyCannotDecrypt
        }
        return clearText
    }
	
	public func getExternalPublicKey() -> SecKey? {
		importedPublicKey
	}
}
