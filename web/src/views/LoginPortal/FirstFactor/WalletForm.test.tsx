// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { postWalletBegin, postWalletRedeem, postWalletStatus } from "@services/Wallet";
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

vi.mock("qrcode.react", () => ({
    QRCodeSVG: (props: { value: string }) => <span data-testid="qr" data-value={props.value} />,
}));

vi.mock("@services/Wallet", async (importOriginal) => ({
    ...(await importOriginal<typeof import("@services/Wallet")>()),
    postWalletBegin: vi.fn(),
    postWalletRedeem: vi.fn(),
    postWalletStatus: vi.fn(),
}));

const allFlows = ["same_device", "cross_device"];

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
    vi.mocked(postWalletStatus).mockReset();
});

describe("WalletForm", () => {
    it("should offer the redirect and QR flows", () => {
        renderForm();

        expect(screen.getByRole("button", { name: /on this device/ })).toBeInTheDocument();
        expect(screen.getByRole("button", { name: /on another device/ })).toBeInTheDocument();
    });

    it("should offer only the configured flows", () => {
        renderForm({ flows: ["cross_device"] });

        expect(document.getElementById("wallet-cross-device-button")).not.toBeNull();
        expect(document.getElementById("wallet-same-device-button")).toBeNull();
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

    it("should show the QR code and poll until the wallet answers", async () => {
        vi.mocked(postWalletBegin).mockResolvedValue({ link: "openid4vp://?request_uri=x" });
        vi.mocked(postWalletStatus)
            .mockResolvedValueOnce({ pending: true })
            .mockResolvedValueOnce({ redirect: "https://app.example.com" });

        const props = renderForm();

        fireEvent.click(document.getElementById("wallet-cross-device-button")!);

        await waitFor(() =>
            expect(screen.getByTestId("qr")).toHaveAttribute("data-value", "openid4vp://?request_uri=x"),
        );
        await waitFor(() => expect(props.onAuthenticationSuccess).toHaveBeenCalledWith("https://app.example.com"), {
            timeout: 6000,
        });

        expect(postWalletStatus).toHaveBeenCalledTimes(2);
        expect(screen.queryByTestId("qr")).toBeNull();
    }, 10000);

    it("should stop the QR flow on cancel", async () => {
        vi.mocked(postWalletBegin).mockResolvedValue({ link: "openid4vp://?request_uri=x" });

        const props = renderForm();

        fireEvent.click(document.getElementById("wallet-cross-device-button")!);
        await waitFor(() => expect(screen.getByTestId("qr")).toBeInTheDocument());

        fireEvent.click(document.getElementById("wallet-cancel-button")!);

        expect(screen.queryByTestId("qr")).toBeNull();
        expect(props.onAuthenticationStop).toHaveBeenCalledTimes(1);
        expect(postWalletStatus).not.toHaveBeenCalled();
    });
});
