package com.norulesweb.authapp.core.model.common;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.Column;
import javax.persistence.EntityListeners;
import javax.persistence.MappedSuperclass;
import java.time.Instant;

@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class AuditableModelBase extends ModelBase {

    protected Instant createdOn;

    protected Instant updatedOn;

//    protected AppUser createdBy;
//
//    protected AppUser updatedBy;

    public AuditableModelBase() { }

    public AuditableModelBase(AuditableModelBase auditableModelBase) {
        super(auditableModelBase);
        setCreatedOn(auditableModelBase.getCreatedOn());
        setUpdatedOn(auditableModelBase.getUpdatedOn());
//        setCreatedBy(auditableModelBase.getCreatedBy());
//        setUpdatedBy(auditableModelBase.getUpdatedBy());
    }

    /**
     * Date created
     */
    @CreatedDate
    @Column(name="CREATED_ON_UTC", nullable=false)
    public Instant getCreatedOn() {
        return createdOn;
    }

    public void setCreatedOn(Instant createdOn) {
        this.createdOn = createdOn;
    }

    /**
     * Date last modified
     */
    @LastModifiedDate
    @Column(name="UPDATED_ON_UTC")
    public Instant getUpdatedOn() {
        return updatedOn;
    }

    public void setUpdatedOn(Instant updatedOn) {
        this.updatedOn = updatedOn;
    }

    /**
     * Created by user
     */
//    @CreatedBy
//    @ManyToOne(fetch = FetchType.LAZY, optional = false)
//    @JoinColumn(name="CREATED_BY_STUDENT_TRACKER_USER_ID")
//    public AppUser getCreatedBy() {
//        return createdBy;
//    }
//
//    public void setCreatedBy(AppUser createdBy) {
//        this.createdBy = createdBy;
//    }
//
//    /**
//     * Last modified by user
//     */
//    @LastModifiedBy
//    @ManyToOne(fetch = FetchType.LAZY, optional = true)
//    @JoinColumn(name="UPDATED_BY_STUDENT_TRACKER_USER_ID")
//    public AppUser getUpdatedBy() {
//        return updatedBy;
//    }
//
//    public void setUpdatedBy(AppUser updatedBy) {
//        this.updatedBy = updatedBy;
//    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .appendSuper(super.toString())
                .append("createdOn", createdOn)
                //.append("createdBy", createdBy)
                .append("updatedOn", updatedOn)
                //.append("updatedBy", updatedBy)
                .toString();
    }
}

