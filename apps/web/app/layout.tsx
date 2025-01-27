import type { Metadata } from 'next'
import { jetbrainsMono } from '@/lib/fonts'
import './globals.css'
import '@/lib/fonts/fonts.css'
import '@avelin/ui/globals.css'
import Providers from '@/providers'
import { Toaster } from '@avelin/ui/sonner'
import QueryClientProvider from '@/providers/query-client-provider'
import CommandMenu from '@/components/command-menu/command-menu'

export const metadata: Metadata = {
  title: 'Avelin',
  description: 'Code together, right now.',
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang='en'>
      {/* <head> */}
      {/*   <script */}
      {/*     src='https://unpkg.com/react-scan/dist/auto.global.js' */}
      {/*     async */}
      {/*   /> */}
      {/* </head> */}
      <body
        className={`${jetbrainsMono.variable} font-sans bg-color-background h-screen w-screen`}
      >
        <QueryClientProvider>
          <Providers>
            {children}
            <Toaster richColors />
            <CommandMenu />
          </Providers>
        </QueryClientProvider>
      </body>
    </html>
  )
}
