-- Synthetic policy fixture. It is never applied to a database.
create policy synthetic_read on public.synthetic_table for select using (true);
