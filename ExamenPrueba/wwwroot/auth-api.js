const authForms = new Set(["register", "login", "logout"]);

document.addEventListener("submit", async event => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) {
        return;
    }

    const operation = form.dataset.authApi;
    if (!authForms.has(operation)) {
        return;
    }

    event.preventDefault();
    const submitters = [...form.querySelectorAll("button[type='submit'], input[type='submit']")];
    submitters.forEach(button => button.disabled = true);
    showError(form, null);

    try {
        const token = await getAntiforgeryToken(form);
        const request = createRequest(form, operation, token);
        const response = await fetch(`/api/auth/${operation}`, request);
        if (!response.ok) {
            throw new Error(await readError(response));
        }

        if (operation === "register") {
            const payload = await response.json();
            const target = new URL("/Account/RegisterConfirmation", location.origin);
            target.searchParams.set("email", payload.email);
            const returnUrl = new URL(location.href).searchParams.get("ReturnUrl");
            if (returnUrl) {
                target.searchParams.set("ReturnUrl", returnUrl);
            }
            location.assign(target.href);
            return;
        }

        if (operation === "login") {
            const returnUrl = new URL(location.href).searchParams.get("ReturnUrl");
            location.assign(localTarget(returnUrl, "/dashboard"));
            return;
        }

        const returnUrl = form.elements.namedItem("ReturnUrl")?.value;
        location.assign(localTarget(returnUrl, "/"));
    } catch (error) {
        showError(form, error instanceof Error ? error.message : "No fue posible completar la operación.");
        submitters.forEach(button => button.disabled = false);
    }
});

async function getAntiforgeryToken(form) {
    const formToken = form.elements.namedItem("__RequestVerificationToken")?.value;
    if (formToken) {
        return formToken;
    }

    const response = await fetch("/api/auth/antiforgery", {
        credentials: "same-origin",
        headers: { "Accept": "application/json" }
    });
    if (!response.ok) {
        throw new Error("No fue posible preparar la protección antiforgery.");
    }

    const payload = await response.json();
    return payload.token;
}

function createRequest(form, operation, token) {
    const request = {
        method: "POST",
        credentials: "same-origin",
        headers: {
            "Accept": "application/json",
            "X-CSRF-TOKEN": token
        }
    };

    if (operation === "register") {
        request.headers["Content-Type"] = "application/json";
        request.body = JSON.stringify({
            email: fieldValue(form, "Input.Email"),
            password: fieldValue(form, "Input.Password"),
            confirmPassword: fieldValue(form, "Input.ConfirmPassword"),
            returnUrl: new URL(location.href).searchParams.get("ReturnUrl")
        });
    } else if (operation === "login") {
        request.headers["Content-Type"] = "application/json";
        request.body = JSON.stringify({
            email: fieldValue(form, "Input.Email"),
            password: fieldValue(form, "Input.Password"),
            rememberMe: Boolean(form.elements.namedItem("Input.RememberMe")?.checked)
        });
    }

    return request;
}

function fieldValue(form, name) {
    return form.elements.namedItem(name)?.value ?? "";
}

async function readError(response) {
    const contentType = response.headers.get("Content-Type") ?? "";
    if (contentType.includes("json")) {
        const payload = await response.json();
        if (payload.errors) {
            return Object.values(payload.errors).flat().join(" ");
        }
        return payload.detail ?? payload.title ?? `La operación devolvió HTTP ${response.status}.`;
    }

    const message = await response.text();
    return message || `La operación devolvió HTTP ${response.status}.`;
}

function localTarget(value, fallback) {
    try {
        const target = new URL(value || fallback, `${location.origin}/`);
        return target.origin === location.origin
            ? `${target.pathname}${target.search}${target.hash}`
            : fallback;
    } catch {
        return fallback;
    }
}

function showError(form, message) {
    const element = form.querySelector("#auth-api-error") ??
        document.querySelector("#auth-api-error");
    if (!element) {
        return;
    }

    element.textContent = message ?? "";
    element.classList.toggle("d-none", !message);
}
