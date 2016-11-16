package com.norulesweb.authapp.core.model.common;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.springframework.data.annotation.Id;

import javax.persistence.Column;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.MappedSuperclass;

/**
 * A base model class for most StudentTracker models.
 */
@MappedSuperclass
public abstract class ModelBase implements IIdentifiable {

    /**
     * The cached hash code value for this instance.
     */
    private int hashValue = 0;

    /**
     * Database ID for this object
     */
    protected Long id = null;

    public ModelBase() { }

    public ModelBase(Long id) {
        setId(id);
    }

    public ModelBase(ModelBase modelBase) {
        setId(modelBase.getId());
    }

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "ID")
    public Long getId() {
        return id;
    }

    public void setId(Long val) {
        id = val;
    }

    /**
     * Implementation based on compatible types and equality of primary key values.
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null)
            return false;

        if (!(obj instanceof ModelBase))
            return false;

        ModelBase that = (ModelBase)obj;

        // Without Hibernate-defined ids equality is based on reference
        if (id == null || that.id == null)
            return super.equals(that);

        // Models with different ids cannot be equal
        if (id != that.id)
            return false;

        Class<?> thisType = getClass();
        Class<?> thatType = that.getClass();

        // The objects are equal if the type of one is descended from the other's
        return thisType.isAssignableFrom(thatType)
                || thatType.isAssignableFrom(thisType);
    }

    /**
     * Implementation based on the Bloch pattern.
     */
    @Override
    public int hashCode() {
        // Calculate the hash code if we haven't already
        if (hashValue == 0) {
            if (id == null) {
                hashValue = System.identityHashCode(this);
            } else {
                int result = 17;
                int idValue = id.hashCode();
                result = result * 37 + idValue;

                hashValue = result;
            }
        }
        return hashValue;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("id", id)
                .toString();
    }
}

