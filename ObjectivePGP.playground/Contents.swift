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


let signedText = """
-----BEGIN PGP MESSAGE-----

hQIMA74XoJw9RGwyAQ//auCZ+DnXYMf59E9gHv/afeJT1snj+QbNtJ4al4Mo9s4g
CRq6f4sE6dfH/o0kMMav8LyQKemcjC25mqzztX7ODy0m+NT0Netig7dq2FobJ+M6
3smShcEc+K12g0KhmZg4Ea//07cqEfgkiMCHaxt7lgqdDez8M4ofGzj5GdL7lmZa
57dSQGRq2DrXCXD6yWxNpRxC7rkqASzn6m8sqqG3WP812lgaSquHTR9omAUAgjh6
fT7d2UhZdCIxZ4na/jpLQtEX8LnHzQE0qxk8nQYDrVIPMvpFcejdLmxKBpLDhiSI
kZPttUUYhdY02VGUpLUG3QFQNUhTwha3NUZYgu2XbfW3mWCJ5ARFzbL3Ram0FxuD
RGVA3meV9oxMmwKsOC8Iyu8bkY4KVBTCcIZRnlxcvz5rYpIHM/2hZRj98HFPcbuy
4KpmY6blT9gX8i3f4JEOPjEu9uwKaXbSkm/lAwxoPuTl3geye5fSmucyx9+kj985
hdg55jE8Elo8FfX4XRPyULvkQ6PuOfCu6qZA06wOzvyZyJEw7Rxd7RtIUsPsHkF6
LJxF66Ss4jclBXPrJ23VLs8rgLzzAO1Bz86PHkcMS+reI4+YAou/e4Q+8ryS0Kc0
cB8y/vyLEwAuCbPIPqlfdOuaDBBfszu+durCu3tIHDcZ466WQ3PNC+x14VnLFZHS
wQ4BmxLqRGYq9Iqt5ScjhG50q+c1WjOjgmkFOFEbP4pATF6Hz9Qayw626/5v+1rJ
MK1m5NKwYHEnzCNUYuuG/naUX/gP2HFRbk3Yjx6syYZ2ulgiOUrtj8p4EpsoemnL
2QRJOHWuZB5DK5hUeEoO23VEHh+ZR+3UD7Ipi/HKhhrCHWEZ3keRSRmtRcmpZ6MX
uquMMFHdaZUTX/0DtQ2w+fqyUlyGsk1CIJw72lTkmsSxAXjJABMvxqJ7x85WB/z6
hZS8rxq9qwPosbNxL389BYxlf8vc0kTNCJKiXW9ZSRP5TZLXk4A5Fb6BpbzRBZcy
HiheOH6iIbNI2654Fgj8a79vyZkMhPfyft/udFL0Iq0wfG8Y2G+k3D7vIzClo5h2
frGn9i+epzobI1dGy9h3eOiJYNp4lTn6JM9LcKWyunbBF5k/omlY7ZfqIXjNGG3E
grqV/+B5mHSfs5/RRBBG/QynQzO38zk1mLUEn+QIe+SYsZCNijRwntlKJ96ru+Zs
EvYL6Lkdx7FAxSXKveVBB0xGvDjETEEljHrJbzE3ByROo9QvjvTKhhLB3Nj9eN/3
rETVf+co1Uh7bV3ZARr9Yx0roa26c0pqNxSocE/g8B0=
=HME2
-----END PGP MESSAGE-----
"""
let msg = "signed msg"

if let path = Bundle.main.path(forResource: "alice", ofType: "asc"), let data = msg.data(using: .utf8) {
    let keys = try ObjectivePGP.readKeys(fromPath: path)
    
    let signedMsg = try ObjectivePGP.sign(data, detached: true, using: keys, passphraseForKey: nil)
    let armored = Armor.armored(signedMsg, as: PGPArmorType.signature)
    do {
         let x = try ObjectivePGP.decrypt(signedMsg, andVerifySignature: true, using: keys, passphraseForKey: nil)
        try ObjectivePGP.verify(data, withSignature: signedMsg, using: keys, passphraseForKey: nil)
    } catch {
        print(error)
    }
   
}




