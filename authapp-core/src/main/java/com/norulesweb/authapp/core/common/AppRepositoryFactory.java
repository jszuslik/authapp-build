package com.norulesweb.authapp.core.common;

import org.springframework.data.jpa.repository.support.JpaEntityInformation;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;
import org.springframework.data.repository.core.RepositoryInformation;
import org.springframework.data.repository.core.RepositoryMetadata;

import javax.persistence.EntityManager;
import java.io.Serializable;

public class AppRepositoryFactory<T, I extends Serializable> extends JpaRepositoryFactory {

    private EntityManager entityManager;

    public AppRepositoryFactory(EntityManager entityManager) {
        super(entityManager);
        this.entityManager = entityManager;
    }

    @Override
    @SuppressWarnings("unchecked")
    protected Object getTargetRepository(RepositoryInformation metadata) {
        return new AppRepositoryImpl<>((JpaEntityInformation<T, I>) getEntityInformation(metadata.getDomainType()), entityManager);
    }

    @Override
    protected Class<?> getRepositoryBaseClass(RepositoryMetadata metadata) {
        return AppRepository.class;
    }

}
