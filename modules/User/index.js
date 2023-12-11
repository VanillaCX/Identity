const {Schema, ShortText, Squid} = require("@VanillaCX/SchemaCX");
const {DEKSQuery, SaltsQuery, UsersQuery, KEKSQuery} = require("../Queries")
const {OTPAuth} = require("../OneTimePassword")
const DEK = require("../DEK")

class User {
    #senstive;
    constructor({userData, DEK, masterKey} = {}){
        this.userData = userData;
        this.#senstive = {
            DEK,
            masterKey
        }

        this.OTP = new OTPAuth(this.userData.otp);

    }

    get hasRegisteredOTP(){
        return this.userData.settings.registeredOTP
    }

    async encryptProfile(){
        const key = this.#senstive.DEK;
        const plaintext = JSON.stringify(this.userData);

        console.log("ENCRYPTING...", plaintext);

        return await DEK.encrypt({
            key,
            plaintext 
        })
    }

    async registerOTP(otp){
        if(this.userData.settings.registeredOTP){
            throw new Error("ALREADY_VALIDATED")
        }

        const valid = this.OTP.check(otp);

        if(!valid){
            throw new Error("INVALID_OTP")
        }

        // Register as validated
        this.userData.settings.registeredOTP = true;

        // Encrypt profile
        const encryptedUserData = await this.encryptProfile();

        // Save Encrypted User Profile
        await UsersQuery.updateOne({uuid: this.#senstive.masterKey}, {userData: encryptedUserData})

        return true
    }

    
}

module.exports = { User }