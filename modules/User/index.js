const {UsersQuery} = require("../Queries")
const {OTPAuth} = require("../OneTimePassword")
const DEK = require("../DEK")

class User {
    #senstive;
    constructor({data, DEK, masterKey} = {}){
        this.data = data;
        this.#senstive = {
            DEK,
            masterKey
        }

        this.OTP = new OTPAuth(this.data.otp);

    }

    toJson(){
        return {
            data: this.data,
            DEK: this.#senstive.DEK,
            masterKey: this.#senstive.masterKey
        };
    }

    get screenname(){
        return this.data.screenname;
    }

    get hasRegisteredOTP(){
        return this.data.settings.registeredOTP
    }

    async encryptProfile(){
        const key = this.#senstive.DEK;
        const plaintext = JSON.stringify(this.data);

        console.log("ENCRYPTING...", plaintext);

        return await DEK.encrypt({
            key,
            plaintext 
        })
    }

    async registerOTP(otp){
        if(this.data.settings.registeredOTP){
            throw new Error("ALREADY_VALIDATED")
        }

        const valid = this.OTP.check(otp);

        if(!valid){
            throw new Error("INVALID_OTP")
        }

        // Register as validated
        this.data.settings.registeredOTP = true;

        // Encrypt profile
        const encryptedData = await this.encryptProfile();

        // Save Encrypted User Profile
        await UsersQuery.updateOne({uuid: this.#senstive.masterKey}, {data: encryptedData})

        return true
    }

    
}

module.exports = { User }