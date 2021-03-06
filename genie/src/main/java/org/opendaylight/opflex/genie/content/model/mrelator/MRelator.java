package org.opendaylight.opflex.genie.content.model.mrelator;

import org.opendaylight.opflex.genie.engine.model.*;

/**
 * Created by midvorki on 8/5/14.
 */
public class MRelator
        extends MRelatorItem
{
    /**
     * category identifying all relator rules
     */
    public static final Cat MY_CAT = Cat.getCreate("rel:relator");

    /**
     * category identifying the target class of this relationship rule object
     */
    public static final RelatorCat TARGET_CAT = RelatorCat.getCreate("rel:relator:sourceref", Cardinality.SINGLE);

    /**
     * declares containment relationship.
     *
     * @param aInTargetGName global name of the target class
     * @param aInSourceGName global name of the source class
     * @return pair of relator and related objects
     */
    public static Pair<MRelator, MRelated> addRule(
            RelatorType aInType,
            String aInName,
            String aInSourceGName,
            PointCardinality aInSourceCard,
            String aInTargetGName)
    {
        MRelator lSrc = MRelator.get(aInSourceGName, true);
        MTarget lTarget = lSrc.getMTarget(aInTargetGName, true);

        new MRelationship(
                lTarget,
                aInName,
                aInType,
                aInSourceCard);

        MRelated lContr = MRelated.addRule(aInTargetGName, aInSourceGName);

        return new Pair<>(lSrc,lContr);
    }

    /**
     * Constructor
     * @param aInSourceGname global name of the relator object class
     */
    private MRelator(String aInSourceGname)
    {
        super(MY_CAT, null, TARGET_CAT, aInSourceGname);
    }

    /**
     * Finds Relator rule corresponding to the global name of the class passed in.
     * If aInCreateIfNotFound is true and rule is not found, rule is created.
     * @param aInGName global name of the relator object class
     * @param aInCreateIfNotFound indicates that the rule needs to be created if not found.
     * @return relator rule associated with class identified by the global named passed in.
     */
    public static synchronized MRelator get(String aInGName, boolean aInCreateIfNotFound)
    {
        MRelator lContd = get(aInGName);
        if (null == lContd && aInCreateIfNotFound)
        {
            lContd = new MRelator(aInGName);
        }
        return lContd;
    }

    /**
     * Finds Relator rule corresponding to the global name of the class passed in.
     * @param aInGName global name of the relator object class
     * @return relator rule associated with class identified by the global named passed in.
     */
    public static MRelator get(String aInGName)
    {
        return (MRelator) MY_CAT.getItem(aInGName);
    }

    /**
     * retrieves a rule specified per specific target identified by corresponding class's global name
     * @param aInClassGName global name of the target class
     */
    public MTarget getMTarget(String aInClassGName)
    {
        return (MTarget) getChildItem(MTarget.MY_CAT,aInClassGName);
    }

    /**
     * retrieves a rule specified per specific target identified by corresponding class's global name
     * @param aInClassGName global name of the target class
     * @param aInCreateIfNotFound specifies need of creation, if the rue is not found
     */
    public synchronized MTarget getMTarget(String aInClassGName, boolean aInCreateIfNotFound)
    {
        MTarget lMTarget = getMTarget(aInClassGName);
        if (null == lMTarget && aInCreateIfNotFound)
        {
            lMTarget = new MTarget(this, aInClassGName);
        }
        return lMTarget;
    }

}