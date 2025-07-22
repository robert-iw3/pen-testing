import { auth } from "@/lib/auth";
import { redirect } from "next/navigation";

export default async function RootLayout({ children }) {
  const session = await auth();

  if (!session) redirect("/auth/signin");

  return <>{children}</>;
}
