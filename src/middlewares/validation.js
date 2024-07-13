import { z } from "zod";

export const userSchema = z.object({
  first_name: z.string().min(3),
  last_name: z.string().min(1),
  email: z
    .string()
    .email()
    .transform((val) => val.toLocaleLowerCase()),
  password: z.string().min(6),
  is_active: z.boolean(),
  interests: z.nullable(),
  provider: z.string().nullable(),
  provider_id: z.string().nullable(),
});

export const loginSchema = z.object({
  email: z
    .string()
    .email()
    .transform((val) => val.toLocaleLowerCase()),
  password: z.string().min(),
});

export const forgotSchema = z.object({
  email: z
    .string()
    .email()
    .transform((val) => val.toLocaleLowerCase()),
});

export const resetSchema = z.object({
  user_id: z.string(),
  token: z.string(),
  password: z.string(),
});

export const hackathonSchema = z.object({
  title: z.string(),
  description: z.string().nullable(),
  type: z.string(),
  start_date: z.string(),
  end_date: z.string(),
  prize: z.string().nullable(),
  min_members: z.number(),
  max_members: z.number(),
  tags: z.string(),
  overview: z.string().nullable(),
  rules: z.string().nullable(),
  updates: z.string().nullable(),
  resources: z.string().nullable(),
  company: z.string(),
  status: z.string(),
  created_by: z
    .string()
    .email()
    .transform((val) => val.toLocaleLowerCase()),
});
