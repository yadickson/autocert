package com.github.yadickson.autocert.algorithm;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.github.yadickson.autocert.model.Algorithm;

@RunWith(MockitoJUnitRunner.class)
public class AlgorithmMapperTest {

    private AlgorithmMapper mapper;

    @Before
    public void setUp() {
        mapper = new AlgorithmMapper();
    }

    @Test
    public void it_should_return_rsa_enum_when_input_is_rsa_string_upper_case() {
        String algorithm = "RSA";

        Algorithm result = mapper.apply(algorithm);

        Assert.assertNotNull(result);
        Assert.assertEquals(Algorithm.RSA, result);
    }

    @Test
    public void it_should_return_rsa_enum_when_input_is_rsa_string_lower_case() {
        String algorithm = "rsa";

        Algorithm result = mapper.apply(algorithm);

        Assert.assertNotNull(result);
        Assert.assertEquals(Algorithm.RSA, result);
    }

    @Test
    public void it_should_return_rsa_enum_when_input_is_rsa_string_mix_case() {
        String algorithm = "RsA";

        Algorithm result = mapper.apply(algorithm);

        Assert.assertNotNull(result);
        Assert.assertEquals(Algorithm.RSA, result);
    }

    @Test
    public void it_should_return_rsa_enum_when_input_is_rsa_string_with_spaces() {
        String algorithm = " RsA ";

        Algorithm result = mapper.apply(algorithm);

        Assert.assertNotNull(result);
        Assert.assertEquals(Algorithm.RSA, result);
    }

    @Test
    public void it_should_return_ec_enum_when_input_is_ec_string_upper_case() {
        String algorithm = "EC";

        Algorithm result = mapper.apply(algorithm);

        Assert.assertNotNull(result);
        Assert.assertEquals(Algorithm.EC, result);
    }

    @Test
    public void it_should_return_ecdh_enum_when_input_is_ecdh_string_upper_case() {
        String algorithm = "ECDH";

        Algorithm result = mapper.apply(algorithm);

        Assert.assertNotNull(result);
        Assert.assertEquals(Algorithm.ECDH, result);
    }

    @Test
    public void it_should_return_ecdsa_enum_when_input_is_ecdsa_string_upper_case() {
        String algorithm = "ECDSA";

        Algorithm result = mapper.apply(algorithm);

        Assert.assertNotNull(result);
        Assert.assertEquals(Algorithm.ECDSA, result);
    }

    @Test(expected = AlgorithmNotSupportException.class)
    public void it_should_throw_error_when_input_is_not_supported() {
        String algorithm = "ABCD";

        mapper.apply(algorithm);
    }

}
