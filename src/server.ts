import express, { Request, Response, NextFunction } from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import { generateJwt, generateRandomCode, isValidRedirectUri } from "./utils";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;

const authCodes = new Map<string, string>(); 
const refreshTokens = new Map<string, string>(); 


app.use(bodyParser.urlencoded({ extended: true }));

const CLIENT_ID = "upfirst";
const REDIRECT_URI = "http://localhost:8081/process";

app.get("/api/oauth/authorize", async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
        const { response_type, client_id, redirect_uri, state } = req.query;

        if (response_type !== "code") {
            throw new Error("unsupported_response_type");
        }
        if (client_id !== CLIENT_ID) {
            throw new Error("invalid_client");
        }
        if (!isValidRedirectUri(redirect_uri as string)) {
            throw new Error("invalid_redirect_uri");
        }

        const authCode = generateRandomCode();
        authCodes.set(authCode, client_id);

        let redirectUrl = `${redirect_uri}?code=${authCode}`;
        if (state) {
            redirectUrl += `&state=${state}`;
        }
        res.redirect(redirectUrl);
    } catch (error) {
        next(error);
    }
});

app.post("/api/oauth/token", async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
        const { grant_type, code, client_id, redirect_uri, refresh_token } = req.body;

        if (grant_type === "authorization_code") {
            if (!authCodes.has(code)) {
                throw new Error("invalid_grant");
            }
            if (client_id !== CLIENT_ID || redirect_uri !== REDIRECT_URI) {
                throw new Error("invalid_client");
            }

            const accessToken = await generateJwt({ client_id });
            const newRefreshToken = generateRandomCode();
            refreshTokens.set(newRefreshToken, client_id);

            authCodes.delete(code);

            res.json({
                access_token: accessToken,
                token_type: "bearer",
                expires_in: 3600,
                refresh_token: newRefreshToken,
            });
            return;
        }

        if (grant_type === "refresh_token") {
            if (!refreshTokens.has(refresh_token)) {
                throw new Error("invalid_grant");
            }

            const newAccessToken = await generateJwt({ client_id });

            res.json({
                access_token: newAccessToken,
                token_type: "bearer",
                expires_in: 3600,
            });
            return;
        }

        throw new Error("unsupported_grant_type");
    } catch (error) {
        next(error);
    }
});

app.use((err: Error, req: Request, res: Response, next: NextFunction): void => {
    res.status(500).json({ errors: [{ message: err.message || "Something went wrong" }] });
});

app.listen(PORT, () => {
    console.log(`OAuth 2.0 Server running at http://localhost:${PORT}`);
});
