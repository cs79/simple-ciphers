# globals:

# for English, target squared sum of letter frequencies:
TARGET_SQ_FREQ = 0.065

# valid ciphertext alphabet:
CIPHER_ALPHA = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
                "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"]

# valid plaintext alpha:
PLAIN_ALPHA = [str.lower(i) for i in CIPHER_ALPHA]

# ciphertext alphabet size:
ALPHA_SIZE = 26

# alphabet frequency distribution (English):
ALPHA_FREQ = {0:  0.082,
              1:  0.015,
              2:  0.028,
              3:  0.042,
              4:  0.127,
              5:  0.022,
              6:  0.020,
              7:  0.061,
              8:  0.070,
              9:  0.001,
              10: 0.008,
              11: 0.040,
              12: 0.024,
              13: 0.067,
              14: 0.075,
              15: 0.019,
              16: 0.001,
              17: 0.060,
              18: 0.063,
              19: 0.090,
              20: 0.028,
              21: 0.010,
              22: 0.024,
              23: 0.020,
              24: 0.001,
              25: 0.001}

# sample ciphertexts provided by Katz & Lindell:
mono_cipher = "JGRMQOYGHMVBJWRWQFPWHGFFDQGFPFZRKBEEBJIZQQOCIBZKLFAFGQVFZFWWE\
OGWOPFGFHWOLPHLRLOLFDMFGQWBLWBWQOLKFWBYLBLYLFSFLJGRMQBOLWJVFP\
FWQVHQWFFPQOQVFPQOCFPOGFWFJIGFQVHLHLROQVFGWJVFPFOLFHGQVQVFILE\
OGQILHQFQGIQVVOSFAFGBWQVHQWIJVWJVFPFWHGFIWIHZZRQGBABHZQOCGFHX"

shift_cipher = "OVDTHUFWVZZPISLRLFZHYLAOLYL"


# functions:

def decode_one(char, k, alpha_size):
    '''
    Decode a single enciphered letter for key k with alphabet size alpha_size.
    '''
    return (CIPHER_ALPHA.index(char) - k) % alpha_size

def decode_shifted(c, k, alpha_size):
    '''
    Calculate plaintext for cyphertext c using key k with alphabet size of alpha_size.
    '''
    p = []
    for char in c:
        p.append(decode_one(char, k, alpha_size))
    return p

def stringify_decoded(p):
    '''
    Convenience function for parsing a decoded string back into text form.
    '''
    buf = [PLAIN_ALPHA[i] for i in p]
    return "".join(buf)

def numify_ciphertext(c):
    '''
    Converts ciphertext to numerical format for simpler processing.
    '''
    return [CIPHER_ALPHA.index(i) for i in c]

def numify_plaintext(p):
    '''
    Converts plaintext to numerical format for simpler processing.
    '''
    return [PLAIN_ALPHA.index(i) for i in p]

def calc_squared_freq(num_text, alpha_size):
    '''
    Pure tabulation on numeric text to calculate squared character frequency.
    Useful for statistical attacks on Vigenere cipher.
    '''
    cum_freq = 0
    text_len = len(num_text)
    for i in range(0, alpha_size):
        cum_freq += (len([j for j in num_text if j == i]) / text_len) ** 2
    return cum_freq

def calc_cand_sq_freq(c, k, alpha_size):
    '''
    For candidate key k, calculate plaintext squared frequency sum.
    This assumes that k was the correct decoding key, and "squares" the frequency
    by multiplying by the English frequency of the corresponding plaintext character.
    '''
    cum_freq = 0
    c_num = numify_ciphertext(c)
    text_len = len(c)
    for i in range(0, alpha_size):
        q_i = len([j for j in c_num if j == i]) / text_len
        cum_freq += (q_i * ALPHA_FREQ[(i - k) % alpha_size])
    # debug:
    # print("Candidate k:\t\t{}\nSquared frequency:\t{}".format(k, cum_freq))
    return cum_freq

def calc_all_candidate_sf(c, alpha_size):
    '''
    Performs statistical attack on shift cipher for all candidate keys.
    The candidate key with the minimum absolute distance from the target squared
    frequency of characters (for English) is used for decoding of the returned
    plaintext.
    '''
    cands = []
    for i in range(0, alpha_size):
        cands.append(calc_cand_sq_freq(c, i, alpha_size))
    # debug:
    # print("Candidate frequencies:\t{}".format(cands))
    dists = [abs(cand - TARGET_SQ_FREQ) for cand in cands]
    # find minimum distance candidate:
    best_cand = None
    current_min = max(dists)
    for i in range(0, len(dists)):
        if dists[i] < current_min:
            best_cand = i
            current_min = dists[i]
    print("Best-guess candidate squared frequency: {}".format(cands[best_cand]))
    best_cand_plaintext = stringify_decoded(decode_shifted(c, best_cand, alpha_size))
    print("Decrypted text for best candidate:\n{}".format(best_cand_plaintext))
    return best_cand_plaintext

def encipher_vigenere(k, p, alpha_size):
    '''
    Enciphers plaintext p using key k and the Vigenere cipher.
    Returns the numeric encoding for composability.
    '''
    p_num = numify_plaintext(p)
    k_string = "".join([k for i in range(0, len(p_num) // len(k) + 1)])
    k_num = numify_plaintext(k_string)[:len(p_num)]
    c_num = [(p_num[i] + k_num[i]) % alpha_size for i in range(len(p_num))]
    return c_num

def extract_stream(n, k_len, c):
    '''
    Extracts the nth stream from ciphertext c (in numeric / list form),
    assuming a period of k_len for separating the streams.
    Stream numbering starts at 0 and goes through k_len - 1.
    '''
    assert n < k_len, "n must be less than k_len"
    stream = []
    for i in range(len(c)):
        if i % k_len == n:
            stream.append(c[i])
    return stream

def ioc_attack(c, max_k_len, alpha_size):
    '''
    TODO: for presumed k length 1..max_k_len, extract some stream (say the 0th)
    then check the value of calc_squared_freq() on that stream; after obtaining
    this value for all candidate key lengths, check which are closest to target
    frequency and if there is some periodicity to this. May need heuristics for
    choosing the "best" candidate period, but try simple rounding to start with
    '''

# demonstrate the attacks:

# Statistical attack on shift cipher: should return "howmanypossiblekeysarethere"
calc_all_candidate_sf(shift_cipher, ALPHA_SIZE)

# Statistical attack on Vigenere cipher
# hopefully sufficiently long string to demonstrate an attack:
plain = "sciencefromlatinscientiaknowledgeisasystematicenterprisethatbuildsandorganizesknowledgeintheformoftestableexplanations" +\
         "andpredictionsabouttheuniversetheearliestrootsofsciencecanbetracedtoancientegyptandmesopotamiainaroundthreethousandto" +\
         "twelvehundredbcetheircontributionstomathematicsastronomyandmedicineenteredandshapedgreeknaturalphilosophyofclassical" +\
         "antiquitywherebyformalattemptsweremadetoprovideexplanationsofeventsinthephysicalworldbasedonnaturalcausesafterthefall" +\
         "ofthewesternromanempireknowledgeofgreekconceptionsoftheworlddeterioratedinwesterneuropeduringtheearlycenturiesfour" +\
         "hundredtoonethousandceofthemiddleagesbutwaspreservedinthemuslimworldduringtheislamicgoldenagetherecoveryandassimilation" +\
         "ofgreekworksandislamicinquiriesintowesterneuropefromthetenthtothirteenthcenturyrevivednaturalphilosophywhichwaslater" +\
         "transformedbythescientificrevolutionthatbeganinthesixteenthcenturyasnewideasanddiscoveriesdepartedfrompreviousgreek" +\
         "conceptionsandtraditionsthescientificmethodsoonplayedagreaterroleinknowledgecreationanditwasnotuntilthenineteenthcentury" +\
         "thatmanyoftheinstitutionalandprofessionalfeaturesofsciencebegantotakeshapealongwiththechangingofnaturalphilosophytonatural" +\
         "sciencemodernscienceistypicallydividedintothreemajorbranchesthatconsistofthenaturalsciencesbiologychemistryandphysicswhich" +\
         "studynatureinthebroadestsensethesocialscienceseconomicspsychologyandsociologywhichstudyindividualsandsocietiesandtheformal" +\
         "scienceslogicmathematicsandtheoreticalcomputersciencewhichdealwithsymbolsgovernedbyrulesthereisdisagreementhoweveronwhether" +\
         "theformalsciencesactuallyconstituteascienceastheydonotrelyonempiricalevidencedisciplinesthatuseexistingscientificknowledge" +\
         "forpracticalpurposessuchasengineeringandmedicinearedescribedasappliedsciencesnewknowledgeinscienceisadvancedbyresearchfrom" +\
         "scientistswhoaremotivatedbycuriosityabouttheworldandadesiretosolveproblemscontemporaryscientificresearchishighly" +\
         "collaborativeandisusuallydonebyteamsinacademicandresearchinstitutionsgovernmentagenciesandcompaniesthepracticalimpactof" +\
         "theirworkhasledtotheemergenceofsciencepoliciesthatseektoinfluencethescientificenterprisebyprioritizingthedevelopmentof" +\
         "commercialproductsarmamentshealthcarepublicinfrastructureandenvironmentalprotection"

c_vigenere = encipher_vigenere("queen", plain, ALPHA_SIZE)
