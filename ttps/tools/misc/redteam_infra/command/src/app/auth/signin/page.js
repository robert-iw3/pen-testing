import { SigninForm } from "@/components/authentication/signin-form";
import { auth } from "@/lib/auth";
import Image from "next/image";
import Link from "next/link";
import { redirect } from "next/navigation";

export default async function Signin() {
  const session = await auth();
  if (session) redirect("/projects");

  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-6 bg-muted p-6 md:p-10">
      <div className="flex w-full max-w-sm flex-col gap-6">
        <Link
          href="https://docs.lodestar-forge.com"
          target="_blank"
          className="flex items-center gap-2 self-center font-medium"
        >
          <Image src="/logo-small.png" height={24} width={24} alt="Logo" />
          Lodestar Forge
        </Link>
        <SigninForm />
      </div>
    </div>
  );
}
