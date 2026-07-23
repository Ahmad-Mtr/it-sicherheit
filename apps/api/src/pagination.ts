import { t } from "elysia";

export const paginationQuery = {
  limit: t.Optional(t.Numeric({ minimum: 1, maximum: 100, default: 20 })),
  offset: t.Optional(t.Numeric({ minimum: 0, default: 0 })),
};

export function paginationMeta(total: number, limit: number, offset: number) {
  return { total, limit, offset, hasMore: offset + limit < total };
}
