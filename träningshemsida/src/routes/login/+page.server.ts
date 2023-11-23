import { error, redirect, fail } from '@sveltejs/kit';
import { PrismaClient } from '@prisma/client';
import type { Actions, PageServerLoad } from './$types';
import * as crypto from "crypto";// Function to generate a new salt and hash a password

const prisma = new PrismaClient();

export const load = (async () => {
    return {};
}) satisfies PageServerLoad;

export const actions: Actions = {
    login:async (request, cookies) => {
        let data = await request.formData();
        let username = data.get("username")?.toString();
        let password = data.get("username")?.toString();

        if (username && password) {
            const existingUser = await prisma.user.findUnique({
                where: { name:username }
            });
            if (existingUser) {
                // Handle already logged in
                if (validatePassword(password, existingUser.salt, existingUser.hash)) {
                    cookies.set("username", username, { secure: false });
                    throw redirect(307, "/"); // login
                } else {
                    return fail(400, {password: "you need a password!!!"})
                }
            } else {
                // Create a new user in the database
                const { salt, hash } = hashPassword(password);
                await prisma.user.create({
                    data: { 
                        name: username, 
                        password: password,
                        salt: salt,
                        hash: hash,
                    },
                });
                cookies.set("username", username);                
            }
        }
        

        
    }
    
};
logout:async (cookies) => {
    let username = cookies.get("username")
    if (username) {
        cookies.delete(username)
    }
    else{
        throw new Error("no username and password")
    }

}
function hashPassword(password: crypto.BinaryLike) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return { salt, hash };
}

function validatePassword(inputPassword: crypto.BinaryLike, storedSalt: crypto.BinaryLike, storedHash: string) {
    const hash = crypto.pbkdf2Sync(inputPassword, storedSalt, 1000, 64, 'sha512').toString('hex');
    return storedHash === hash;
}
