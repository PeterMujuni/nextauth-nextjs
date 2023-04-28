import NextAuth from "next-auth";
import GithubProvider from "next-auth/providers/github";
import GoogleProvider from "next-auth/providers/google";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import { PrismaClient } from "@prisma/client";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcrypt";

const prisma = new PrismaClient();

export default NextAuth({
	adapter: PrismaAdapter(prisma),
	providers: [
		GoogleProvider({
			clientId: process.env.GOOGLE_ID as string,
			clientSecret: process.env.GOOGLE_SECRET as string,
		}),
		GithubProvider({
			clientId: process.env.GITHUB_ID as string,
			clientSecret: process.env.GITHUB_SECRET as string,
		}),
		CredentialsProvider({
			name: "credentials",
			credentials: {
				email: { label: "Email", type: "text" },
				password: { label: "Password", type: "password" },
			},
			async authorize(credentials) {
				if (!credentials?.email || !credentials?.password) {
					throw new Error("Invalid credentials");
				}

				const user = await prisma.user.findUnique({
					where: {
						email: credentials.email,
					},
				});

				if (!user || !user?.hashedPassword) {
					throw new Error("Invalid credentials");
				}

				const isCorrectPassword = await bcrypt.compare(
					credentials.password,
					user.hashedPassword
				);

				if (!isCorrectPassword) {
					throw new Error("Invalid credentials");
				}

				return user;
			},
		}),
	],

	pages: {
		signIn: "/auth/signin"
	},

	debug: process.env.NODE_ENV === "development",
	session: {
		strategy: "jwt"
	},
	secret: process.env.NEXTAUTH_SECRET,
	// database: process.env.DATABASE_URL,
});


// providers: [
//     CredentialsProvider({
//       name: "Credentials",

//       credentials: {
//         username: { label: "Username", type: "text", placeholder: "jsmith" },
//         password: { label: "Password", type: "password" },
//       },
//       async authorize(credentials, req) {
//         // Add logic here to look up the user from the credentials supplied

//         const res = await fetch("http://localhost:8000/auth/login", {
//           method: "POST",
//           headers: {
//             "Content-Type": "application/json",
//           },
//           body: JSON.stringify({
//             username: credentials?.username,
//             password: credentials?.password,
//           }),
//         });
//         const user = await res.json();

//         if (user) {
//           return user;
//         } else {
//           return null;
//         }
//       },
//     }),
//   ],

//   pages: {
//     signIn: "/auth/signIn",
//   },