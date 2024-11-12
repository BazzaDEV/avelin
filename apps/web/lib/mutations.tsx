import { useMutation } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { toast } from '@avelin/ui/sonner'
import { LOGOUT_ACTION_TOAST_ID } from './constants'
import { KeyRoundIcon } from '@avelin/icons'

export const useCreateRoom = () =>
  useMutation({
    mutationFn: async () => {
      const res = await api.rooms.create.$post()
      return await res.json()
    },
  })

export const useLogout = () =>
  useMutation({
    mutationKey: ['auth', 'logout'],
    mutationFn: async () => {
      const res = await api.auth.logout.$post()

      if (res.status >= 400) {
        const { error } = (await res.json()) as { error: string }
        throw new Error(error)
      }
    },
    onMutate: () => {
      toast('Logging out...', {
        id: LOGOUT_ACTION_TOAST_ID,
        icon: <KeyRoundIcon className='size-4 shrink-0 animate-bounce' />,
      })
    },
  })