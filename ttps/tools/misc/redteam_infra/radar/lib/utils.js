import jwt from "jsonwebtoken";

const generateAccessToken = () => {
    return jwt.sign(
        { id: "1e768b85-061c-42db-b466-d875001135eb" },
        process.env.NUCLEUS_SECRET,
    );
};

export async function apiFetch(path, method = "GET", body) {
    try {
        const accessToken = generateAccessToken();
        if (!path) return false;
        if (body !== undefined) body = JSON.stringify(body);
        const response = await fetch(
            `http://nucleus:${process.env.NUCLEUS_PORT}${path}`,
            {
                method,
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${accessToken}`,
                },
                body,
            },
        );
        if (!response.ok) return false;
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1)
            return await response.json();

        return true;
    } catch (e) {
        console.error(e);
        return false;
    }
}
