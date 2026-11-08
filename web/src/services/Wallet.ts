// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

import {
    FirstFactorWalletBeginPath,
    FirstFactorWalletDigitalCredentialsPath,
    FirstFactorWalletRedeemPath,
    FirstFactorWalletStatusPath,
} from "@services/Api";
import { Post, PostWithOptionalResponse } from "@services/Client";
import { SignInResponse } from "@services/SignIn";

export const WalletMethodSameDevice = "same_device";
export const WalletMethodCrossDevice = "cross_device";
export const WalletMethodDigitalCredentials = "digital_credentials";

export const WalletResponseCodeParam = "response_code";

export interface WalletBeginOptions {
    method: string;
    keepMeLoggedIn: boolean;
    targetURL?: string;
    requestMethod?: string;
    flowID?: string;
    flow?: string;
    subflow?: string;
    userCode?: string;
}

export interface WalletDigitalCredentialsRequest {
    protocol: string;
    data: unknown;
}

export interface WalletBeginResponse {
    link?: string;
    request?: WalletDigitalCredentialsRequest;
}

export type WalletStatusResponse = { pending: boolean } | SignInResponse;

export function isWalletPending(response: WalletStatusResponse): boolean {
    return response !== undefined && "pending" in response && response.pending;
}

export async function postWalletBegin(options: WalletBeginOptions, signal?: AbortSignal) {
    return Post<WalletBeginResponse>(FirstFactorWalletBeginPath, options, signal);
}

export async function postWalletStatus(signal?: AbortSignal) {
    return PostWithOptionalResponse<WalletStatusResponse>(FirstFactorWalletStatusPath, undefined, signal);
}

export async function postWalletRedeem(responseCode: string) {
    return PostWithOptionalResponse<SignInResponse>(FirstFactorWalletRedeemPath, { responseCode });
}

export async function postWalletDigitalCredentials(data: unknown, signal?: AbortSignal) {
    return PostWithOptionalResponse<SignInResponse>(FirstFactorWalletDigitalCredentialsPath, { data }, signal);
}

export function isDigitalCredentialsSupported(): boolean {
    return "DigitalCredential" in globalThis;
}

export async function getDigitalCredential(
    request: WalletDigitalCredentialsRequest,
    signal?: AbortSignal,
): Promise<unknown> {
    const options = {
        digital: { requests: [{ data: request.data, protocol: request.protocol }] },
        mediation: "required",
        signal,
    } as CredentialRequestOptions;

    const credential = (await navigator.credentials.get(options)) as unknown as { data: unknown } | null;

    if (credential === null) {
        throw new Error("The browser did not return a credential");
    }

    return credential.data;
}
