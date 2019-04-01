// Build ObjectivePGP target first.
import ObjectivePGP
import Foundation

// Generate new key
let key1 = KeyGenerator().generate(for: "marcin@krzyzanowskim.com", passphrase: nil)
let key2 = KeyGenerator().generate(for: "fran@krzyzanowskim.com", passphrase: nil)

let plaintext = Data(bytes: [1,2,3,4,5])

// Encrypt 5 bytes using selected key
let encryptedBin = try ObjectivePGP.encrypt(plaintext, addSignature: false, using: [key1, key2])
let encrypted = Armor.armored(encryptedBin, as: .message)
print(encrypted)

// Sign the encrypted binary
let signatureBin = try ObjectivePGP.sign(encryptedBin, detached: true, using: [key1])
let signature = Armor.armored(signatureBin, as: .signature)
print(signature)

try ObjectivePGP.verify(encryptedBin, withSignature: signatureBin, using: [key1])

let decrypted = try ObjectivePGP.decrypt(encryptedBin, andVerifySignature: false, using: [key1])
print("Decrypted : \(Array(decrypted))")


var keys = [Key]()
if let path = Bundle.main.path(forResource: "sender", ofType: "asc"){
    keys.append(contentsOf: try ObjectivePGP.readKeys(fromPath: path))
    print(keys.count)
}
else {
    print("No sender keys")
}

if let path = Bundle.main.path(forResource: "alice", ofType: "asc"){
    keys.append(contentsOf: try ObjectivePGP.readKeys(fromPath: path))
}

func testSig(text: String, sig: String) {
    if let sigData = sig.data(using: .utf8) {
        var text = text.replacingOccurrences(of: "\r\n", with: "\n")
        text = text.replacingOccurrences(of: "\n", with: "\r\n")
        text = text.trimmingCharacters(in: .whitespaces)
        //Replace whitespaces with tab
        text = text.replacingOccurrences(of: "    ", with: "\t")
        do {
            try ObjectivePGP.verify(text.data(using: .utf8)!, withSignature: sigData, using: keys, passphraseForKey: nil)
            print("Works!")
        } catch {
            print(error)
        }
    }
}





