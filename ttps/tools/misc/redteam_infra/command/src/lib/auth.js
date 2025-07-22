import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";

async function selectUser(email) {
    // const user = await db.select().from(users).where(eq(users.email, email));
    if (user.length > 0) return user[0];
    return null;
}

const providers = [
    Credentials({
        credentials: {
            username: { label: "Username" },
            password: { label: "Password", type: "password" },
        },
        async authorize(c) {
            const { email, password } = c;
            if (!email || !password) {
                return null;
            }

            const response = await fetch(
                `http://nucleus:${process.env.NUCLEUS_PORT}/auth/login`,
                {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email, password }),
                },
            );

            if (!response.ok) return null;
            return (await response.json()) ?? null;
        },
    }),
];

const pages = {
    signIn: "/auth/signin",
};

const callbacks = {
    jwt({ token, user }) {
        if (user) {
            // User is available during sign-in
            return { ...token, id: user.id, accessToken: user.accessToken };
        }

        return token;
    },
    session({ session, token }) {
        session.user.id = token.id;
        session.accessToken = token.accessToken;

        // Delete unnecessary information from JWT
        delete session.user.image;

        return session;
    },
};

export const { handlers, signIn, signOut, auth } = NextAuth({
    providers,
    pages,
    callbacks,
    secret: process.env.COMMAND_SECRET,
});
