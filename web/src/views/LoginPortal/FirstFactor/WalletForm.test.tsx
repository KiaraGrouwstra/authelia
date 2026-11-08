// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

import { render, screen, waitFor } from "@testing-library/react";

import { postWalletBegin, postWalletRedeem } from "@services/Wallet";
import WalletForm from "@views/LoginPortal/FirstFactor/WalletForm";

const mocks = vi.hoisted(() => ({
    queryParams: {} as Record<string, null | string>,
    setSearchParams: vi.fn(),
}));

vi.mock("react-i18next", () => ({
    useTranslation: () => ({ t: (key: string) => key }),
}));

vi.mock("react-router", () => ({
    useSearchParams: () => [new URLSearchParams(), mocks.setSearchParams],
}));

vi.mock("@hooks/QueryParam", () => ({
    useQueryParam: (name: string) => mocks.queryParams[name] ?? null,
}));

vi.mock("@hooks/Flow", () => ({
    useFlow: () => ({ flow: "flow", id: "flow-id", subflow: "subflow" }),
}));

vi.mock("@hooks/OpenIDConnect", () => ({
    useUserCode: () => "user-code",
}));

vi.mock("@services/Wallet", async (importOriginal) => ({
    ...(await importOriginal<typeof import("@services/Wallet")>()),
    postWalletBegin: vi.fn(),
    postWalletRedeem: vi.fn(),
}));

const allFlows = ["same_device"];

function renderForm(props: Partial<{ disabled: boolean; flows: string[] }> = {}) {
    const merged = {
        disabled: false,
        flows: allFlows,
        onAuthenticationError: vi.fn(),
        onAuthenticationStart: vi.fn(),
        onAuthenticationStop: vi.fn(),
        onAuthenticationSuccess: vi.fn(),
        rememberMe: true,
        ...props,
    };

    render(<WalletForm {...merged} />);

    return merged;
}

beforeEach(() => {
    mocks.queryParams = {};
    mocks.setSearchParams.mockReset();
    vi.mocked(postWalletBegin).mockReset();
    vi.mocked(postWalletRedeem).mockReset();
});

describe("WalletForm", () => {
    it("should offer the redirect flow", () => {
        renderForm();

        expect(screen.getByRole("button", { name: /on this device/ })).toBeInTheDocument();
    });

    it("should render nothing when no configured flow can run", () => {
        renderForm({ flows: [] });

        expect(screen.queryByRole("button")).toBeNull();
    });

    it("should redeem a response code once and remove it from the URL", async () => {
        mocks.queryParams = { response_code: "code" };
        vi.mocked(postWalletRedeem).mockResolvedValue({ redirect: "https://app.example.com" });

        const props = renderForm();

        await waitFor(() => expect(props.onAuthenticationSuccess).toHaveBeenCalledWith("https://app.example.com"));

        expect(postWalletRedeem).toHaveBeenCalledTimes(1);
        expect(postWalletRedeem).toHaveBeenCalledWith("code");
        expect(mocks.setSearchParams).toHaveBeenCalledTimes(1);
    });

    it("should report a failed redeem", async () => {
        mocks.queryParams = { response_code: "code" };
        vi.mocked(postWalletRedeem).mockRejectedValue(new Error("refused"));
        vi.spyOn(console, "error").mockImplementation(() => {});

        const props = renderForm();

        await waitFor(() => expect(props.onAuthenticationError).toHaveBeenCalledTimes(1));

        expect(props.onAuthenticationSuccess).not.toHaveBeenCalled();
    });
});
