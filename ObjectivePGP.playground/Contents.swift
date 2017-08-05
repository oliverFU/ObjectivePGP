// Build ObjectivePGP target first.
import ObjectivePGP
import Foundation
import Cocoa


print("start")
let pgp = ObjectivePGP()

pgp.generateKey("Dave <dave@enzevalos.de>")

print("\nFinish")
