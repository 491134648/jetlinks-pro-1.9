package org.jetlinks.pro.device.tenant;

import org.jetlinks.pro.device.entity.ProtocolSupportEntity;
import org.jetlinks.pro.device.service.DeviceGroupService;
import org.jetlinks.pro.tenant.Asset;
import org.jetlinks.pro.tenant.AssetSupplier;
import org.jetlinks.pro.tenant.AssetType;
import org.jetlinks.pro.tenant.supports.DefaultAsset;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

@Component
public class DeviceGroupAssetSupplier implements AssetSupplier {

    private final DeviceGroupService groupService;

    public DeviceGroupAssetSupplier(DeviceGroupService groupService) {
        this.groupService = groupService;
    }

    @Override
    public List<AssetType> getTypes() {
        return Collections.singletonList(DeviceAssetType.protocol);
    }

    @Override
    public Flux<DefaultAsset> getAssets(AssetType type, Collection<?> assetId) {
        return groupService.createQuery()
            .where()
            .in(ProtocolSupportEntity::getId, assetId)
            .fetch()
            .map(ps -> new DefaultAsset(ps.getId(), ps.getName(), DeviceAssetType.protocol));
    }
}
