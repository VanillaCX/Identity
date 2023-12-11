const otplib = require("otplib").authenticator;
const qrcode  = require("qrcode");


const generate = (username, service) => {
    // Create otpauth
    const totp = OTPAuth.generateSecret();
    const key = OTPAuth.keyuri(username, service, totp);

    return key;
}



class OTPAuth {
    constructor({secretKey, username, service = "Vanilla CX"} = {}){
        this.secretKey = secretKey;
        this.username = username;
        this.service = service;
    }

    get toJson() {
        return {
            secretKey: this.secretKey,
            username: this.username,
            service: this.service,
        }
    }

    get otp(){
        return otplib.generate(this.secretKey);
    }

    get keyURI(){
        return otplib.keyuri(this.username, this.service, this.secretKey)
    }

    async getQRCode(){
        return await qrcode.toDataURL(this.keyURI)
    }

    check(otp){
        return otplib.check(otp, this.secretKey);
    }

    static create(username, service){
        // Create a new OTP secret
        const secretKey = otplib.generateSecret();

        return new OTPAuth({
            secretKey,
            username,
            service
        });
    }
}

module.exports = {OTPAuth, generate}