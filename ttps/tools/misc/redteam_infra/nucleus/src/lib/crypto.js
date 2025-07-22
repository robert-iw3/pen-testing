"use strict";

import { customType } from "drizzle-orm/pg-core";
import * as argon2 from "argon2";
import CryptoJS from "crypto-js";

export const hash = async (password) => {
    try {
        const computedHash = await argon2.hash(password);
        return computedHash;
    } catch (err) {
        console.log(err);
    }
};

export const verify = async (hash, password) => {
    try {
        if (await argon2.verify(hash, password)) {
            // password match
            return true;
        } else {
            // password did not match
            return false;
        }
    } catch (err) {
        // internal failure
        console.log(err);
    }
};

export const encryptedText = customType({
    dataType() {
        return "text";
    },
    fromDriver(value) {
        let decrypted = CryptoJS.AES.decrypt(
            value,
            process.env.STORE_ENCRYPTION_KEY,
        ).toString(CryptoJS.enc.Utf8);
        return decrypted;
    },
    toDriver(value) {
        let encrypted = CryptoJS.AES.encrypt(
            value,
            process.env.STORE_ENCRYPTION_KEY,
        ).toString();
        return encrypted;
    },
});
