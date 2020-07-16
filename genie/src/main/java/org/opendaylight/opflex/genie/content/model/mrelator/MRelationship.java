package org.opendaylight.opflex.genie.content.model.mrelator;

import org.opendaylight.opflex.genie.content.model.mclass.MClass;
import org.opendaylight.opflex.genie.content.model.mcont.MContained;
import org.opendaylight.opflex.genie.content.model.mnaming.MNameComponent;
import org.opendaylight.opflex.genie.content.model.mnaming.MNameRule;
import org.opendaylight.opflex.genie.content.model.mnaming.MNamer;
import org.opendaylight.opflex.genie.content.model.module.Module;
import org.opendaylight.opflex.genie.engine.model.Cat;
import org.opendaylight.opflex.genie.engine.model.Item;
import org.opendaylight.opflex.genie.engine.model.Pair;
import org.opendaylight.opflex.modlan.utils.Strings;

/**
 * Created by midvorki on 8/6/14.
 */
public class MRelationship extends Item
{
    public static final Cat MY_CAT = Cat.getCreate("rel:relationship");

    public MRelationship(
            MTarget aInParent,
            String aInName,
            RelatorType aInType,
            PointCardinality aInSourceCard)
    {
        super(MY_CAT, aInParent, aInName);
        String lSrcClassGName = getSourceClassGName();
        int lSlashIdx = lSrcClassGName.indexOf('/');
        moduleName = lSrcClassGName.substring(0, lSlashIdx);
        sourceClassLocalName = lSrcClassGName.substring(lSlashIdx + 1);
        type = aInType;
        sourceCardinality = aInSourceCard;
        initSourceRelnClass();
    }

    public String getSourceClassGName() { return getMRelator().getTargetGName(); }

    public MClass getTargetClass(){ return getMTarget().getTarget(); }

    public MTarget getMTarget() { return (MTarget) getParent(); }
    public MRelator getMRelator() { return getMTarget().getRelator(); }

    public PointCardinality getSourceCardinality() { return sourceCardinality; }

    /*
        source: module/ReSrc<LocalClassName><Name>
        target: module/ReTgt<LocalClassName><Name>
        resolver: module/ReRes<LocalClassName><Name>
     */

    private void initSourceRelnClass()
    {
        if (type.hasSourceObject())
        {
            // CLASS NAME FORMAT: module/ReSrc<LocalClassName><Name>
            Pair<MRelationshipClass,Boolean> lRes = initClass(type.isNamed() ? "relator/NameResolvedRelSource" : "relator/DirectRelSource");
            MClass lClass = lRes.getFirst();

            MContained.addRule(getSourceClassGName(), lClass.getGID().getName());

            if (lRes.getSecond()) // IS NEW
            {
                MNamer lNamer = MNamer.get(lClass.getGID().getName(), true);
                MNameRule lNr = lNamer.getNameRule(Strings.ASTERISK,true);

                switch (getSourceCardinality())
                {
                    case SINGLE:

                        new MNameComponent(lNr, null);
                        break;

                    case MANY:

                        // TODO: FIX NAMING: IF ONLY ONE CLASS IS CONTAINED IN THIS RELN, NO NEED FOR CLASS, JUST NEED NAME...
                        new MNameComponent(lNr, "targetClass");
                        new MNameComponent(lNr, "targetName");
                        break;
                }
            }
            // TODO: PROPERTIES
        }
    }

    private Pair<MRelationshipClass,Boolean> initClass(String aInSuperClass)
    {
        String lClassName = sourceClassLocalName + "To" + Strings.upFirstLetter(getLID().getName()) + "RSrc";
        Module lModule = Module.get(moduleName, true);
        MRelationshipClass lClass = (MRelationshipClass) lModule.getChildItem(MRelationshipClass.MY_CAT,lClassName);
        boolean isNew = null == lClass;
        if (isNew)
        {
            lClass = new MRelationshipClass(lModule, lClassName, this);
            lClass.addSuperclass(aInSuperClass);
        }
        else
        {
            lClass.addTargetRelationship(this);
        }
        return new Pair<>(lClass,isNew);
    }

    private final RelatorType type;
    private final PointCardinality sourceCardinality;
    private final String moduleName;
    private final String sourceClassLocalName;
}
