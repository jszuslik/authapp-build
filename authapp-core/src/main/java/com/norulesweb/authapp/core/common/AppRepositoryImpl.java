package com.norulesweb.authapp.core.common;

import org.springframework.data.jpa.repository.support.JpaEntityInformation;
import org.springframework.data.jpa.repository.support.QueryDslJpaRepository;
import org.springframework.data.repository.NoRepositoryBean;

import javax.persistence.EntityManager;
import java.io.Serializable;

@NoRepositoryBean
public class AppRepositoryImpl<T, ID extends Serializable> extends QueryDslJpaRepository<T, ID> implements AppRepository<T, ID> {

    private final EntityManager entityManager;

    public AppRepositoryImpl(JpaEntityInformation<T, ID> entityInformation, EntityManager entityManager) {
        super(entityInformation, entityManager);

        this.entityManager = entityManager;
    }

    @Override
    public void refresh(T model) {
        entityManager.refresh(model);
    }

    @Override
    public void flushAndRefresh(T model) {
        entityManager.flush();
        refresh(model);
    }


}
