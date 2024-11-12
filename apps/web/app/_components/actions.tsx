'use client'

import { LayoutGroup, motion } from 'framer-motion'
import CreateRoomButton from './create-room-button'
import { useAuth } from '@/providers/auth-provider'
import { AuthenticatedActions, UnauthenticatedActions } from './auth-actions'

export function Actions() {
  const { isAuthenticated, isPending, user } = useAuth()

  return (
    <LayoutGroup id='actions'>
      <motion.div
        layout
        className='inline-flex items-center gap-4 mt-4'
      >
        <motion.div layout='position'>
          <CreateRoomButton />
        </motion.div>
        {isPending ? null : isAuthenticated ? (
          <AuthenticatedActions user={user!} />
        ) : (
          <UnauthenticatedActions />
        )}
      </motion.div>
    </LayoutGroup>
  )
}