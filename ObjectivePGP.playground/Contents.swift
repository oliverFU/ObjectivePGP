// Build ObjectivePGP target first.
import ObjectivePGP
import Foundation
import Cocoa


print("start")

guard let keyURL = Bundle.main.url(forResource: "marcin.krzyzanowski@gmail.com", withExtension: "asc"),
    let keyData = try? Data(contentsOf: keyURL) else { fatalError("Can't find key file") }
let msg = "Hi Alice this is Dave!"

let pgp = ObjectivePGP()
pgp.importKeys(from: keyData)
guard let key = pgp.findKey(forIdentifier: "878ECFB866753341") else { fatalError("Can't find the key") }

if let plainData = msg.data(using: .utf8){
    // Encrypt 5 bytes using selected key
    let encryptedArmoredData = try! pgp.encryptData(plainData, using: [key], armored: true)
    let encryptedAscii = String(data: encryptedArmoredData, encoding: .utf8)

    print(encryptedAscii ?? "Missing")
}
let pgpAlice = ObjectivePGP()
let pgpDave = ObjectivePGP()

let dave = pgpDave.generateKey("Dave <dave@enzevalos.de>")
//let alice = pgpAlice.generateKey("alice")

print("Dave: \(dave.keyID) and fingerprint: \(dave.fingerprint) ")
//print("Alice: \(alice.keyID)")

/*
do{
    try pgpDave.importKeys(from: dave.export())
    try pgpDave.importKeys(from: (alice.publicKey?.export())!)
    
    try pgpAlice.importKeys(from: alice.export())
    try pgpAlice.importKeys(from: (dave.publicKey?.export())!)

let msg = "Hi Alice this is Dave!"
print("Message: \(msg)")
if let plainData = msg.data(using: .utf8){
    //let cipherData = try pgpDave.encryptData(plainData, using: [alice], armored: true)
    let cipherData = try pgpDave.sign(plainData, using: dave, passphrase: nil, detached: true)
    if let cipher = String(data: cipherData, encoding: .utf8){
        print("Cipher text: \(cipher))")
    }
    //let unencData = try pgpAlice.decryptData(cipherData, passphrase: nil)
    let correct = try pgpAlice.verifyData(cipherData)
    print(" Could verify message: \(correct)")
    //if let unenc = String(data: unencData, encoding: .utf8){
       // print("Plain text: \(unenc)")
    //}
}


} catch _ { print("Could not import keys, enc or dec")}
 */




print("\nFinish")
