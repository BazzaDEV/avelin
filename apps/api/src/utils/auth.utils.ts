import { invalidateSessionsForUser } from '@avelin/auth'
import { db, eq, schema, Session, sql, User } from '@avelin/database'
import { jwtVerify, SignJWT } from 'jose'
import { pick } from 'remeda'

const AUTH_JWT_SECRET = process.env.AUTH_JWT_SECRET as string

export async function linkAnonymousToRealAccount({
  anonymousUserId,
  userId,
}: {
  anonymousUserId: string
  userId: string
}) {
  // Invalidate anonymous sessions
  await invalidateSessionsForUser(anonymousUserId, { db })

  await db.transaction(async (tx) => {
    // Room participation
    await tx
      .update(schema.roomParticipants)
      .set({
        userId: userId,
      })
      .where(eq(schema.roomParticipants.userId, anonymousUserId))

    // Room ownership
    await tx
      .update(schema.rooms)
      .set({
        creatorId: userId,
      })
      .where(eq(schema.rooms.creatorId, anonymousUserId))

    // Retire anonymous user
    await tx
      .update(schema.users)
      .set({
        retiredAt: sql`now()`,
        linkedUserId: userId,
      })
      .where(eq(schema.users.id, anonymousUserId))
  })
}

export async function createSessionJwt(user: User, session: Session) {
  const jwt = await new SignJWT({
    ...pick(user, ['id', 'email', 'name', 'picture', 'isAnonymous']),
    // roles: ['user'],
    // permissions: ['read', 'write'],
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuedAt()
    .setExpirationTime('1m')
    .sign(new TextEncoder().encode(AUTH_JWT_SECRET))

  return jwt
}

// Utility to decode and validate a JWT
export async function validateSessionJwt(token: string) {
  const { payload } = await jwtVerify(
    token,
    new TextEncoder().encode(AUTH_JWT_SECRET),
  )

  return payload
}
