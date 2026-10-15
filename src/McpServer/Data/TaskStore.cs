using System.Collections.Concurrent;

namespace McpServer.Data;

public sealed record TaskItem(int Id, string Title, string Status, DateTimeOffset CreatedAt);

/// <summary>
/// Per-user task lists, keyed on the token's <c>sub</c> claim. The point of this store is to make
/// identity leakage visible: if two test users ever see the same list, the token subject isn't
/// reaching the tool.
/// </summary>
public sealed class TaskStore
{
    private readonly ConcurrentDictionary<string, List<TaskItem>> _bySubject = new(StringComparer.Ordinal);
    private int _nextId;

    public TaskStore()
    {
        // Distinct seed data per user, so a mix-up is obvious at a glance.
        Seed("user-ada", "Review the analytical engine spec", "Finish the Bernoulli number notes");
        Seed("user-grace", "Debug the Mark II relay", "Write the A-0 compiler docs");
        Seed("user-alan", "Draft the imitation game paper", "Review Bombe rotor wiring");
    }

    public IReadOnlyList<TaskItem> List(string subject) =>
        _bySubject.TryGetValue(subject, out var tasks) ? tasks.AsReadOnly() : [];

    public TaskItem Create(string subject, string title)
    {
        var task = new TaskItem(
            Interlocked.Increment(ref _nextId),
            title,
            "Not started",
            DateTimeOffset.UtcNow);

        _bySubject.AddOrUpdate(
            subject,
            _ => [task],
            (_, existing) =>
            {
                lock (existing)
                {
                    existing.Add(task);
                }

                return existing;
            });

        return task;
    }

    private void Seed(string subject, params string[] titles)
    {
        _bySubject[subject] = titles
            .Select(t => new TaskItem(
                Interlocked.Increment(ref _nextId), t, "Not started", DateTimeOffset.UtcNow))
            .ToList();
    }
}
