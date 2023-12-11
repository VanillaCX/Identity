const {Authenticator} = require("../index.js");




const createAccount = async  (username, password, screenname) => {
    try {
        const myAuthenticator = await Authenticator.createAccount(username, password, screenname)
        console.log(myAuthenticator);
    } catch(error) {
        switch(error.message) {
            case "ACCOUNT_ALREADY_EXISTS":
                console.log(`username: ${username} already exists`);
                break;
            case "SchemaError":
                console.log(`SchemaError:`);
                console.log(error.errors)
                break;
            default:
                console.log(error)
                break;
        }
    }
}

const authenticate = async  (username, password) => {
    try {
        const user = await Authenticator.authenticate(username, password);

        

        const userEnteredOTP = user.OTP.otp;

        console.log("user:", user);
        console.log("user.hasRegisteredOTP:", user.hasRegisteredOTP);

        if(user.hasRegisteredOTP) {
            console.log("Already Registered OTP");
            console.log("Ask for user One Time Password...");

        } else {
            const qrcode = await user.OTP.getQRCode();

            console.group("Display QR Code so user can add to their Authenticator App");
            console.log(qrcode);
            console.groupEnd();

            //await user.registerOTP(userEnteredOTP);
            //console.log("Registered OTP");
        }

    } catch(error) {
        switch(error.message) {
            case "NO_SUCH_ACCOUNT":
                console.log(`username: ${username} doesnt exist`);
                break;
            default:
                console.log(error);
                break;
        }
    }
}


//createAccount("zbowyer", "11PAssword@@", "Zoe");
authenticate("zbowyer", "11PAssword@@");
