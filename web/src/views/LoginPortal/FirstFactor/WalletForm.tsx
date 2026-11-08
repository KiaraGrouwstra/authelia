// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

import { Fragment, useCallback, useEffect, useRef, useState } from "react";

import axios from "axios";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router";

import { Button } from "@components/UI/Button";
import { Separator } from "@components/UI/Separator";
import { Spinner } from "@components/UI/Spinner";
import { RedirectionURL, RequestMethod } from "@constants/SearchParams";
import { useFlow } from "@hooks/Flow";
import { useUserCode } from "@hooks/OpenIDConnect";
import { useQueryParam } from "@hooks/QueryParam";
import { SignInResponse } from "@services/SignIn";
import { WalletMethodSameDevice, WalletResponseCodeParam, postWalletBegin, postWalletRedeem } from "@services/Wallet";

export interface Props {
    disabled: boolean;
    rememberMe: boolean;
    flows: string[];

    onAuthenticationStart: () => void;
    onAuthenticationStop: () => void;
    onAuthenticationError: (_err: Error) => void;
    onAuthenticationSuccess: (_redirectURL: string | undefined) => void;
}

const WalletForm = function (props: Props) {
    const { t: translate } = useTranslation();

    const redirectionURL = useQueryParam(RedirectionURL);
    const requestMethod = useQueryParam(RequestMethod);
    const responseCode = useQueryParam(WalletResponseCodeParam);
    const [, setSearchParams] = useSearchParams();
    const { flow, id: flowID, subflow } = useFlow();
    const userCode = useUserCode();

    const [loading, setLoading] = useState(Boolean(responseCode));

    const abortRef = useRef<AbortController | null>(null);
    const redeemedRef = useRef(false);
    const callbacksRef = useRef(props);
    callbacksRef.current = props;

    useEffect(() => () => abortRef.current?.abort(), []);

    const start = useCallback(() => {
        abortRef.current?.abort();
        abortRef.current = new AbortController();

        callbacksRef.current.onAuthenticationStart();
        setLoading(true);

        return abortRef.current.signal;
    }, []);

    const stop = useCallback(() => {
        setLoading(false);
        callbacksRef.current.onAuthenticationStop();
    }, []);

    const succeed = useCallback(
        (response: SignInResponse) => {
            stop();
            callbacksRef.current.onAuthenticationSuccess(response ? response.redirect : undefined);
        },
        [stop],
    );

    const fail = useCallback(
        (err: unknown) => {
            stop();

            if (axios.isCancel(err)) return;

            console.error(err);
            callbacksRef.current.onAuthenticationError(new Error(translate("The wallet sign in did not succeed")));
        },
        [stop, translate],
    );

    useEffect(() => {
        if (!responseCode || redeemedRef.current) return;

        redeemedRef.current = true;

        setSearchParams(
            (params) => {
                params.delete(WalletResponseCodeParam);
                return params;
            },
            { replace: true },
        );

        callbacksRef.current.onAuthenticationStart();

        postWalletRedeem(responseCode).then(succeed).catch(fail);
    }, [responseCode, setSearchParams, succeed, fail]);

    const handleSignIn = useCallback(
        async (method: string) => {
            if (loading) return;

            const signal = start();

            try {
                const begun = await postWalletBegin(
                    {
                        flow,
                        flowID,
                        keepMeLoggedIn: callbacksRef.current.rememberMe,
                        method,
                        requestMethod,
                        subflow,
                        targetURL: redirectionURL,
                        userCode,
                    },
                    signal,
                );

                if (!begun.link) {
                    throw new Error("The server did not return a wallet link");
                }

                globalThis.location.assign(begun.link);

                // A custom scheme does not unload the page when no wallet handles the link.
                stop();
            } catch (err) {
                fail(err);
            }
        },
        [fail, flow, flowID, loading, redirectionURL, requestMethod, start, stop, subflow, userCode],
    );

    const sameDevice = props.flows.includes(WalletMethodSameDevice);

    if (!sameDevice) return null;

    return (
        <Fragment>
            <div className="w-full">
                <div className="relative flex items-center py-2">
                    <Separator className="flex-1" />
                    <span className="px-3 text-sm uppercase text-muted-foreground">{translate("or")}</span>
                    <Separator className="flex-1" />
                </div>
            </div>
            <div className="flex w-full flex-col gap-2">
                <Button
                    id="wallet-same-device-button"
                    variant="default"
                    className="w-full"
                    onClick={() => handleSignIn(WalletMethodSameDevice)}
                    disabled={props.disabled}
                >
                    {translate("Open the EU Digital Identity Wallet on this device")}
                    {loading ? <Spinner size={20} className="ml-2 h-5 w-5" /> : null}
                </Button>
            </div>
        </Fragment>
    );
};

export default WalletForm;
