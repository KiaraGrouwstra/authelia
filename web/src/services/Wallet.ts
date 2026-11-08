// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

import { FirstFactorWalletBeginPath, FirstFactorWalletRedeemPath } from "@services/Api";
import { Post, PostWithOptionalResponse } from "@services/Client";
import { SignInResponse } from "@services/SignIn";

export const WalletMethodSameDevice = "same_device";

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

export interface WalletBeginResponse {
    link?: string;
}

export async function postWalletBegin(options: WalletBeginOptions, signal?: AbortSignal) {
    return Post<WalletBeginResponse>(FirstFactorWalletBeginPath, options, signal);
}

export async function postWalletRedeem(responseCode: string) {
    return PostWithOptionalResponse<SignInResponse>(FirstFactorWalletRedeemPath, { responseCode });
}
