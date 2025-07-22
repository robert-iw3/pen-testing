import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import { ThemeProvider } from "@/components/common/theme-provider";
import "./globals.css";
import {
    Card,
    CardHeader,
    CardTitle,
    CardDescription,
    CardContent,
} from "@/components/ui/card";

export const metadata = {
    title: "Lodestar Forge",
    description:
        "Easy to use, open-source infrastructure management platform, crafted specifically for red team engagements.",
};

export default function RootLayout({ children }) {
    return (
        <html
            lang="en"
            suppressHydrationWarning
            className={`${GeistSans.variable} ${GeistMono.variable}`}
        >
            <body>
                <ThemeProvider
                    attribute="class"
                    defaultTheme="system"
                    enableSystem
                    disableTransitionOnChange
                >
                    <div className="absolute z-50 bg-muted xl:hidden flex h-screen w-screen items-center justify-center">
                        <Card className="mx-auto max-w-sm">
                            <CardHeader className="text-center">
                                <CardTitle className="text-xl">
                                    Browser Too Small
                                </CardTitle>
                                <CardDescription>
                                    Please resize your browser window to
                                    continue.
                                </CardDescription>
                            </CardHeader>
                        </Card>
                    </div>
                    {children}
                </ThemeProvider>
            </body>
        </html>
    );
}
