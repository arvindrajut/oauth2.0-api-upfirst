import { SignJWT } from "jose";
import { v4 as uuidv4 } from "uuid";

const SECRET_KEY = new TextEncoder().encode("super_secret_key");

export async function generateJwt(payload: { [key: string]: any }): Promise<string> {
    return new SignJWT(payload)
        .setProtectedHeader({ alg: "HS256" })
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(SECRET_KEY);
}

export function generateRandomCode(): string {
    return uuidv4().replace(/-/g, "").substring(0, 10);
}

export function isValidRedirectUri(uri: string): boolean {
    return uri === "http://localhost:8081/process";
} 
