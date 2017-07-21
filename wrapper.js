const OpenPGP = function(){
	const openpgp = require('openpgp'); // use as CommonJS, AMD, ES6 module or via window.openpgp
	openpgp.initWorker({ path:'openpgp.worker.js' }) // set the relative web worker path
	openpgp.config.aead_protect = true // activate fast AES-GCM mode (not yet OpenPGP standard)

	this.generateKeys = async (keyLen, userIds, passphrase)=>{
		let options = {
			userIds: [userIds], // multiple user IDs
			numBits: keyLen, // RSA key size
			passphrase: passphrase // protects the private key
		};

		this.key = await openpgp.generateKey(options);

		this.privateKey = this.key.privateKeyArmored; // '-----BEGIN PGP PRIVATE KEY BLOCK ... '
		this.publicKey = this.key.publicKeyArmored;   // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
		this.passphrase = passphrase;

		this.privKeyObj = openpgp.key.readArmored(this.privateKey).keys[0];
		this.privKeyObj.decrypt(this.passphrase);

		return {publicKey: this.publicKey, privateKey: this.privateKey};
	}

	this.encrypt = async (data, pubkey, sign)=>{
		//this.key.decrypt(this.passphrase);

		let options = {
			data: data,                             // input as String (or Uint8Array)
			publicKeys: openpgp.key.readArmored(pubkey).keys,  // for encryption
		};

		if(sign)
		{
			options.privateKeys = this.privKeyObj;
		}

		return (await openpgp.encrypt(options)).data; // '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'
	}

	this.decryptAndVerifySignature = async (encrypted, keyWhichSigned)=>{
		let options = {
			message: openpgp.message.readArmored(encrypted),     // parse armored message
			privateKey: this.privKeyObj, // for decryption
			publicKeys: openpgp.key.readArmored(keyWhichSigned).keys
		};

		let decrypted = (await openpgp.decrypt(options));

		let valid = true;
		for(let signature of decrypted.signatures)
		{
			if(!signature.valid)
				valid = false;
		}

		return {data: decrypted.data, valid: valid}; // 'Hello, World!'
	}

	this.decrypt = async (encrypted)=>{
		let options = {
			message: openpgp.message.readArmored(encrypted),     // parse armored message
			privateKey: this.privKeyObj // for decryption
		};

		return (await openpgp.decrypt(options)).data; // 'Hello, World!'
	}
};

module.exports = OpenPGP;
