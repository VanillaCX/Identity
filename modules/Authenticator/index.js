require('dotenv').config();

const {Schema, ShortText, Squid, Flag, LongText, Password, SchemaError} = require("@VanillaCX/SchemaCX");
const {User} = require("../User");
const argon2 = require("argon2");
const qrcode  = require("qrcode");
const DEK = require("../DEK")
const KEK = require("../KEK")
const {OTPAuth} = require("../OneTimePassword")
const {Query} = require("@VanillaCX/QueryCX")
const {DEKSQuery, SaltsQuery, UsersQuery, KEKSQuery} = require("../Queries")

const getUserSalts = async (clear_username) => {
    const username = await argon2.hash(clear_username, {salt: Buffer.from(serverSalt)});

    const result = await SaltsQuery.findOne({
        username: username
    })

    return result;
}


const generateSalts = (quantity) => {
    const salts = [];

    for(let n = 0; n < quantity; n++){
        salts.push(Squid.generate())
    }

    return salts;
}

const deriveKeysFromMaster = async (masterKey, username, password, salts) => {
    const keks = Buffer.from(await argon2.hash(`${masterKey}${password}${username}`, {salt: Buffer.from(salts[1])})).toString("base64");
    const users = Buffer.from(await argon2.hash(`${keks}`, {salt: Buffer.from(salts[2])})).toString("base64");
    const email = Buffer.from(await argon2.hash(`${users}`, {salt: Buffer.from(salts[3])})).toString("base64");
    const contacts = Buffer.from(await argon2.hash(`${email}`, {salt: Buffer.from(salts[4])})).toString("base64");
    const content = Buffer.from(await argon2.hash(`${contacts}`, {salt: Buffer.from(salts[5])})).toString("base64");
    const files = Buffer.from(await argon2.hash(`${content}`, {salt: Buffer.from(salts[6])})).toString("base64");
    const deks = Buffer.from(await argon2.hash(`${files}`, {salt: Buffer.from(salts[7])})).toString("base64");

    return {
        keks,
        deks,
        users,
        email,
        contacts,
        content,
        files
    }

}

const serverSalt = "69239f4429f5402fb2e3668f1a7b3de8"; // Get from Azure Secrets


class Authenticator {

    static #schema = new Schema({
        username: {type: ShortText, required: true, minLength: 5},
        password: {type: Password, required: true}
    })

    static get schema(){
        return this.#schema;
    }

    constructor(){}

    static async createAccount(clear_username, clear_password, screenname, service = "Squid CX"){

        const {valid, errors, sanitised} = this.schema.validate({
            username: clear_username,
            password: clear_password,
        });

        if(!valid){
            throw new SchemaError(errors)
        }

        const userExists = await getUserSalts(sanitised.username);

        if(userExists){
            throw new Error("ACCOUNT_ALREADY_EXISTS")
        }

        // To Be Saved 
        const masterKey = Squid.generate();
        const salts = generateSalts(10);

        // Never Saved
        const derivedKeys = await deriveKeysFromMaster(masterKey, sanitised.username, sanitised.password, salts);

        // Encryption Keys
        const {dataEncryptionKey} = await DEK.generateKey();
        const {keyEncryptionKey, keyEncryptionKeyName} = await KEK.generateKey();

        // Encrypt DEK with KEK
        const encryptedDEK = await KEK.encrypt({
            key: keyEncryptionKey,
            plaintext: dataEncryptionKey
        });

        // Generate One Time Password
        const otp = OTPAuth.create(sanitised.username, service).toJson;

        // Base Profile
        const userData = {
            otp,
            settings: {
                registeredOTP: false
            },
            screenname
        }

        const encryptedUserData = await DEK.encrypt({
            key: dataEncryptionKey,
            plaintext: JSON.stringify(userData)
        })

        // Save Data to DataBase

        // Save Encrypted Data encryption Key
        DEKSQuery.insertOne({
            uuid: derivedKeys.deks,
            dataEncryptionKey: encryptedDEK
        })

        // Save Salts
        SaltsQuery.insertOne({
            username: await argon2.hash(sanitised.username, {salt: Buffer.from(serverSalt)}),
            salts
        })

        // Save Encrypted User Profile
        UsersQuery.insertOne({
            uuid: masterKey,
            username: await argon2.hash(sanitised.username, {salt: Buffer.from(salts[0])}),
            password: await argon2.hash(sanitised.password, {salt: Buffer.from(salts[1])}),
            userData: encryptedUserData
        })

        // Save Key Encryption Key Name
        KEKSQuery.insertOne({
            uuid: derivedKeys.keks,
            keyEncryptionKeyName
        })
        
    }

    static async authenticate(clear_username, clear_password){
        const {valid, errors, sanitised} = this.schema.validate({
            username: clear_username,
            password: clear_password,
        });

        if(!valid){
            throw new SchemaError(errors)
        }

        // Open document containing user salts
        const salt_document = await getUserSalts(sanitised.username);

        if(!salt_document){
            throw new ReferenceError("NO_SUCH_ACCOUNT")
        }

        // Get salts
        const salts = salt_document.salts;

        // Hash username
        const username = await argon2.hash(sanitised.username, {salt: Buffer.from(salts[0])})

        // Lookup hashed username in user document
        const user_document = await UsersQuery.findOne({
            username
        })

        if(!user_document){
            throw new ReferenceError("NO_SUCH_USER_DOCUMENT")
        }

        // Hash password
        const hashedPassword = await argon2.hash(sanitised.password, {salt: Buffer.from(salts[1])});

        // Compare hashed password with saved hashed password in loaded user document
        if(hashedPassword !== user_document.password){
            return "INCORRECT_PASSWORD";
        } 

        // Retrieve master key
        const masterKey = user_document.uuid;

        // Derive keys from master key
        const derivedKeys = await deriveKeysFromMaster(masterKey, sanitised.username, sanitised.password, salts);

        // Open certificate document referenced by the derived certificate key
        const kek_document = await KEKSQuery.findOne({
            uuid: derivedKeys.keks
        })
    
        // Open DEK document referenced by the derived DEK key
        const dek_document = await DEKSQuery.findOne({
            uuid: derivedKeys.deks
        });

        // Decrpyt the DEK key with the KEK stored in certificate document
        const decryptedDEK = await KEK.decrypt(kek_document.keyEncryptionKeyName, dek_document.dataEncryptionKey);

        // Decrypt user profile using the decrypted DEK 
        const decryptedUserData = await DEK.decrypt(decryptedDEK, user_document.userData);

        // Successful login
        return new User({
            userData: JSON.parse(decryptedUserData),
            DEK: decryptedDEK,
            masterKey
        });
    }

}


module.exports = { Authenticator }