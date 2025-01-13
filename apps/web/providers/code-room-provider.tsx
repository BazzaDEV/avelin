'use client'

import { createContext, useContext, useState } from 'react'
import { createStore, StoreApi, useStore } from 'zustand'
import * as Y from 'yjs'
import { Awareness } from 'y-protocols/awareness'
import { IndexeddbPersistence } from 'y-indexeddb'
import { HocuspocusProvider, WebSocketStatus } from '@hocuspocus/provider'
import type { Room, User, Session } from '@avelin/database'
import {
  AwarenessChange,
  AwarenessList,
  USER_IDLE_TIMEOUT,
  UserAwareness,
  UserInfo,
} from '@/lib/sync'
import { Language, languages } from '@/lib/constants'
import { toast } from '@avelin/ui/sonner'
import { assignOption, baseColors, generateUniqueName } from '@/lib/rooms'

const CodeRoomContext = createContext<StoreApi<CodeRoomStore> | null>(null)

export interface CodeRoomProviderProps {
  children: React.ReactNode
}

export type CodeRoomState = {
  ydoc: Y.Doc
  awareness?: Awareness
  networkProvider?: HocuspocusProvider
  networkProviderStatus?: WebSocketStatus
  persistenceProvider?: IndexeddbPersistence
  room?: Room
  clientId?: number
  users: Map<number, UserInfo>
  activeUsers: Map<number, number>
  isInitialSyncConnect: boolean
  skipRoomAwarenessChangeEvent: boolean
  roomTitle?: string
  editorLanguage?: Language['value']
  // eslint-disable-next-line
  editorObserver?: (event: Y.YMapEvent<any>) => void
  // eslint-disable-next-line
  roomTitleObserver?: (event: Y.YMapEvent<any>) => void
  usersObserver?: (data: AwarenessChange) => void
}

export type CodeRoomActions = {
  initialize: ({
    room,
    user,
    session,
  }: {
    room: Room
    user?: User
    session?: Session
  }) => void
  destroy: () => void
  setUsers: (users: Map<number, UserInfo>) => void
  setUserActive: (userId: number) => void
  setUserInactive: (userId: number) => void
  cleanIdleUsers: () => void
  setEditorLanguage: (language: Language['value']) => void
  setRoomTitle: (title: string) => void
}

export type CodeRoomStore = CodeRoomState & CodeRoomActions

export const createCodeRoomStore = () =>
  createStore<CodeRoomStore>((set, get) => ({
    ydoc: new Y.Doc(),
    awareness: undefined,
    networkProvider: undefined,
    networkProviderStatus: undefined,
    persistenceProvider: undefined,
    room: undefined,
    clientId: undefined,
    users: new Map<number, UserInfo>(),
    activeUsers: new Map<number, number>(),
    editorLanguage: undefined,
    usersObserver: undefined,
    isInitialSyncConnect: false,
    skipRoomAwarenessChangeEvent: true,
    initialize: ({ room, user, session }) => {
      if (!room) throw new Error('Cannot initialize code room without a room')

      set({ room })

      const { ydoc, networkProvider, persistenceProvider } = get()

      set({ awareness: new Awareness(ydoc) })

      function setupRoomTitleObserver() {
        const metaMap = ydoc.getMap('meta')

        if (!metaMap.has('title')) {
          metaMap.set('title', '')
        }

        // Set the initial room title from Yjs
        set({
          roomTitle: metaMap.get('title') as string,
        })

        // Define the observer function
        // eslint-disable-next-line
        const observer = (event: Y.YMapEvent<any>) => {
          if (event.keysChanged.has('title')) {
            const newTitle = metaMap.get('title') as string
            console.log('Received room title update:', newTitle)
            set({ roomTitle: newTitle })
          }
        }

        metaMap.observe(observer)

        set({ roomTitleObserver: observer })
      }

      function setupEditorLanguageObserver() {
        const editorMap = ydoc.getMap('editor')
        if (!editorMap.has('language')) {
          editorMap.set('language', 'plaintext') // Set your default language here
        }

        // Set the initial editorLanguage state from Yjs
        set({
          editorLanguage: editorMap.get('language') as Language['value'],
        })

        // Define the observer function
        // eslint-disable-next-line
        const observer = (event: Y.YMapEvent<any>) => {
          if (event.keysChanged.has('language')) {
            const newLanguage = editorMap.get('language') as Language['value']
            const languageDetails = languages.find(
              (l) => l.value === newLanguage,
            )
            set({ editorLanguage: newLanguage })
            toast.info(
              `Editor language set to ${languageDetails?.name ?? newLanguage}.`,
            )
          }
        }

        // Add the observer to the 'editor' map
        editorMap.observe(observer)

        // Store the observer for later cleanup
        set({ editorObserver: observer })
      }

      function initializeLocalUserInfo(awareness: Awareness) {
        const currentUserInfo = awareness.getLocalState() as UserAwareness

        if (!!currentUserInfo.user) {
          // Local user info already initialized
          // Do not overwrite with new user info
          return
        }

        const assignedColors = Array.from(awareness.getStates().values()).map(
          ({ user }) => user?.color,
        )

        const color = assignOption(Object.values(baseColors), assignedColors)

        const localUser: UserAwareness['user'] = {
          clientId: awareness.clientID,
          name: user && !user.isAnonymous ? user.name : generateUniqueName(),
          color: color,
          picture:
            user && !user.isAnonymous && !!user.picture
              ? user.picture
              : undefined,
          lastActive: Date.now(),
        }

        awareness.setLocalStateField('user', localUser)

        set({ clientId: awareness.clientID })
      }

      function setupUsersObserver(awareness: Awareness) {
        const initialUsers = [...awareness.getStates()] as AwarenessList
        const initialUsersInfo = initialUsers
          // Initial awareness state can be provided without UserInfo defined
          // Makes sure we only include users with UserInfo
          .filter(
            ([, client]) => client !== undefined && client.user !== undefined,
          )
          .map(([clientId, client]) => {
            return [clientId, client.user!]
          }) as Array<[number, UserInfo]>

        set({
          users: new Map(initialUsersInfo),
        })

        const observer = ({ added, removed }: AwarenessChange) => {
          const { skipRoomAwarenessChangeEvent } = get()

          const newAwareness = [...awareness.getStates()] as AwarenessList

          if (!skipRoomAwarenessChangeEvent) {
            added.forEach((id) => {
              const userAwareness = newAwareness.find(
                ([clientId]) => clientId === id,
              )

              const [, client] = userAwareness!

              toast.info(`${client.user?.name} joined the room.`)
            })

            removed.forEach((id) => {
              const removedUser = get().users.get(id)

              if (!removedUser) return

              // WORKAROUND: Currently, there is an awareness-related bug where a remote user's
              // awareness to be removed, then immediately added again. This happens on some interval.
              //
              // This causes a join toast to be displayed, even though the user has not left the room.
              //
              // As a workaround, we wait a short time (50ms), then check if the user is still in the room.
              // If they are, we display the leave toast.
              setTimeout(() => {
                if (!awareness.getStates().has(id)) {
                  toast.info(`${removedUser.name} left the room.`)
                }
              }, 50)
            })
          }

          set({
            users: new Map(
              newAwareness.map(([clientId, client]) => [
                clientId,
                client.user!,
              ]),
            ),
          })

          if (skipRoomAwarenessChangeEvent) {
            set({ skipRoomAwarenessChangeEvent: false })
          }
        }

        awareness.on('change', observer)

        set({ usersObserver: observer })
      }

      const { awareness } = get()

      initializeLocalUserInfo(awareness!)
      setupUsersObserver(awareness!)

      if (!persistenceProvider) {
        const idbProvider = new IndexeddbPersistence(room.id, ydoc)

        idbProvider.on('synced', (idbPersistence: IndexeddbPersistence) => {
          console.log(
            `Content restored for ${idbPersistence.name} from IndexedDB.`,
          )

          setupRoomTitleObserver()
        })

        set({ persistenceProvider: idbProvider })
      } else {
        console.log('Persistence provider already initialized.')
      }

      if (!networkProvider) {
        const ws = new HocuspocusProvider({
          url: process.env.NEXT_PUBLIC_SYNC_URL as string,
          name: room.id,
          document: ydoc,
          awareness: get().awareness,
          token: session?.id,
          onStatus: ({ status }) => {
            console.log('Avelin Sync - connection status:', status)
            set({ networkProviderStatus: status })
          },
          onConnect: () => {
            set({ isInitialSyncConnect: false })

            setTimeout(() => {
              set({ skipRoomAwarenessChangeEvent: false })
            }, 50)
          },
          onSynced: () => {
            // Only setup editor language after network provider sync.
            //
            // Previously, this was done after local provider sync, which caused an issue in production
            // (or more realistic network scenarios with latency between local and network provider sync).
            // The issue resulted in new users joining a room to reset the room's editor language back
            // to the default since they had not yet synced with the network to receive the actual editor language.
            setupEditorLanguageObserver()
          },
        })

        set({ networkProvider: ws, isInitialSyncConnect: true })
      } else {
        console.log('Network provider already initialized.')
      }
    },
    destroy: () => {
      const {
        ydoc,
        awareness,
        networkProvider,
        persistenceProvider,
        roomTitleObserver,
        editorObserver,
        usersObserver,
      } = get()

      awareness?.destroy()
      ydoc.destroy()
      networkProvider?.awareness?.destroy()
      networkProvider?.disconnect()
      networkProvider?.destroy()
      persistenceProvider?.destroy()

      if (editorObserver) {
        const editorMap = ydoc.getMap('editor')
        editorMap.unobserve(editorObserver)
      }

      if (roomTitleObserver) {
        const metaMap = ydoc.getMap('meta')
        metaMap.unobserve(roomTitleObserver)
      }

      if (usersObserver) {
        networkProvider?.awareness?.off('change', usersObserver)
      }

      set({
        ydoc: new Y.Doc(),
        networkProvider: undefined,
        persistenceProvider: undefined,
        room: undefined,
        clientId: undefined,
        users: new Map<number, UserInfo>(),
        activeUsers: undefined,
        editorLanguage: undefined,
        editorObserver: undefined,
        skipRoomAwarenessChangeEvent: true,
      })
    },
    setUsers: (users) => {
      set({ users: new Map([...users]) })
    },
    setUserActive: (userId) => {
      const { activeUsers } = get()
      activeUsers.set(userId, Date.now())
      set({ activeUsers: new Map([...activeUsers]) })
    },
    setUserInactive: (userId) => {
      const { activeUsers } = get()
      activeUsers.delete(userId)
      set({ activeUsers: new Map([...activeUsers]) })
    },
    cleanIdleUsers: () => {
      const { activeUsers } = get()

      const now = Date.now()
      const users = new Map<number, number>()

      activeUsers.forEach((userId, lastActive) => {
        if (now - lastActive <= USER_IDLE_TIMEOUT) {
          users.set(userId, lastActive)
        }
      })

      set({ activeUsers: users })
    },
    setEditorLanguage: (language) => {
      const { ydoc } = get()

      ydoc.getMap('editor').set('language', language)
    },
    setRoomTitle: (title) => {
      const { ydoc } = get()

      ydoc.getMap('meta').set('title', title)
    },
  }))

export const CodeRoomProvider = ({ children }: CodeRoomProviderProps) => {
  const [store] = useState(() => createCodeRoomStore())

  return (
    <CodeRoomContext.Provider value={store}>
      {children}
    </CodeRoomContext.Provider>
  )
}

export const useCodeRoom = () => {
  const store = useContext(CodeRoomContext)

  if (!store) {
    throw new Error('useCodeRoom must be used within a CodeRoomProvider')
  }

  return useStore(store)
}
