# RSAWrapper
Wrapper class for handling all tasks related to RSA cryptography

USAGE

do {
	let rsaWrapper = try RSAWrapper(with: .RSA2048 , privateTag: "your-private-tag-goes-here")

	let base64PK = try rsaWrapper.publicKeyAsBase64()
	print("public key as base64 -\n \(base64PK)")

	let base64PEM = try rsaWrapper.publicKeyAsPEM()
	print("public key as PEM -\n\(base64PEM)")

	let text2Encrypt = "I want to believe"
	let encryptedText = try rsaWrapper.encrypt(text: text2Encrypt)
	print("encrypted RAW - \(encryptedText)")

	let base64encrypted = try rsaWrapper.encryptBase64(text: text2Encrypt)
	print("encrypted Base64 - \(base64encrypted)")

	var clearText = try rsaWrapper.decrypt(encrypted: encryptedText)
	print("clear Text RAW - \(clearText)")

	clearText = try rsaWrapper.decryptBase64(encryptedBase64: base64encrypted)
	print("clear Text BASE64 - \(clearText)")

	copyFilesFromBundleToDocumentsFolderWith(fileExtension: "der")
	let testDER = documentDirectory?.appendingPathComponent("test.der")
	guard let testDERPath = testDER?.path else { return }
	let externalPK = try? rsaWrapper.importPublicKey(fromDER: testDERPath)
	print("public key from DER certificate -\n \(externalPK)")

} catch {
	print("error happened")
}
