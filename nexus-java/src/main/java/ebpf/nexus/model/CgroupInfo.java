package ebpf.nexus.model;

import java.util.Objects;

/**
 * Represents a cgroup snapshot at a point in time.
 */
public class CgroupInfo {

    /** Cgroup identifier. */
    private long id;

    /** Cgroup path in the hierarchy, e.g. {@code /sys/fs/cgroup/user.slice}. */
    private String path;

    /** Hierarchy ID this cgroup belongs to. */
    private int hierarchyId;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CgroupInfo that = (CgroupInfo) o;
        return id == that.id;
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return String.format("Cgroup{id=%d, path=%s, hierarchy=%d}", id, path, hierarchyId);
    }

    /**
     * Checks whether this cgroup state differs from another snapshot.
     *
     * @param other previous cgroup state, or {@code null} for first-time comparison
     * @return {@code true} if the cgroup path or hierarchy changed
     */
    public boolean hasChangedFrom(CgroupInfo other) {
        if (other == null) return true;
        return !Objects.equals(this.path, other.path)
                || this.hierarchyId != other.hierarchyId;
    }

    public Long getId() {
        return id;
    }
}