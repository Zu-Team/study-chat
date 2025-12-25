# Database Migration Instructions

## Problem
The session ID is being saved to cookies but not to the database because the `sessions` table is missing the `session_id` column and other required columns.

## Solution
Run the SQL migration script to update the `sessions` table structure.

## Steps to Apply Migration

### Option 1: Using Supabase Dashboard (Recommended)

1. Open your Supabase project dashboard
2. Go to **SQL Editor** (in the left sidebar)
3. Click **New Query**
4. Copy and paste the contents of `UpdateSessionsTable.sql`
5. Click **Run** (or press Ctrl+Enter)
6. Verify the migration succeeded

### Option 2: Using psql Command Line

```bash
psql "Host=db.uqqnqosybkmptahljxqu.supabase.co;Port=5432;Database=postgres;Username=postgres;Password=YOUR_PASSWORD" -f UpdateSessionsTable.sql
```

## What the Migration Does

1. **Adds `session_id` column** - Stores the GUID session ID from cookies
2. **Makes `user_id` nullable** - Allows anonymous sessions (null before login)
3. **Makes `title` nullable** - Optional for anonymous sessions
4. **Adds tracking columns**:
   - `ip_address` - User's IP address
   - `user_agent` - Browser information
   - `last_accessed_at` - Last time session was used
5. **Creates indexes** - For faster lookups on `session_id` and `user_id`
6. **Updates foreign key** - Allows null `user_id` values

## Verification

After running the migration, verify the table structure:

```sql
SELECT column_name, data_type, is_nullable 
FROM information_schema.columns 
WHERE table_name = 'sessions' 
ORDER BY ordinal_position;
```

You should see:
- `session_id` (varchar, not null)
- `user_id` (int8, nullable)
- `title` (text, nullable)
- `ip_address` (varchar, nullable)
- `user_agent` (varchar, nullable)
- `last_accessed_at` (timestamptz, not null)

## Troubleshooting

### Error: "column session_id already exists"
- The migration has already been run. You can skip this step.

### Error: "cannot alter column user_id"
- There might be existing data. The migration handles this, but if it fails, you may need to:
  1. Set all existing `user_id` values to a valid user ID, or
  2. Temporarily remove the NOT NULL constraint manually

### After Migration: Sessions Still Not Saving
- Check application logs for database errors
- Verify the connection string is correct
- Ensure the migration completed successfully

