# WebGoat.NET labels

Source of truth: `WebGoat/Web.sitemap` (the lesson list) and the code behind each active lesson and the WebGoat Coins portal,
read at the pinned commit. Paths start with `WebGoat/`. Both database providers (SQLite and MySQL) are labeled because both ship.
Safe labels: the `Fixed*` variants the lessons ship (`FixedLoadCity`, `FixedLoadComments`) and the parameterized queries.

Not labeled, with the reason:
- Lessons commented out of the sitemap (CSRF, client-side storage, JSON/jQuery injection, Flash, web services, final challenges):
  their code-behind files are empty stubs.
- `GetOrders`, `GetPayments`, `GetProductsAndCategories` and `UpdateCustomerPassword` concatenate an `int` or a Base64 string, so they are
  not injectable and are not labeled either way.
- Customer number cookie trusted as identity (MainPage, Orders, ChangePassword): not a documented lesson.
- `Web.config` `debug="true"` and the Forms-auth `protection` settings: deployment configuration.
- `Code/SQLite*Provider.cs`, `VeryWeakRandom.cs` (not referenced by any lesson), view state, trace and session lessons: no documented
  vulnerable code line.
- WebGoat.NET has no LICENSE file at this commit; nothing is vendored.
