# openpgpWrapper.js
little wrapper around the npm's openpgp module

```javascript
const OpenPGP = require('wrapper.js');

(async()=>{
	let pgp = new OpenPGP();
	let keys = await pgp.generateKeys(512, { name:'Jon Smith', email:'jon@example.com' }, "secret passphrase")

	console.log(keys.privateKey);
	console.log(keys.publicKey);

	let encrypted = await pgp.encrypt("hello world", keys.publicKey, true);
	console.log(encrypted)

	let decrypted = await pgp.decryptAndVerifySignature(encrypted, keys.publicKey);
	console.log(decrypted);
})();
```
